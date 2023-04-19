"""
Copyright(c) 2021, 2022 Bitcoin Association.
Distributed under the Open BSV software license, see the accompanying file LICENSE

Note on typing
--------------

Write database functions are run in the SQLite writer thread using the helper functions from
the `sqlite_database` package, and because of this have to follow the pattern where the database
is an optional last argument.

    ```
    def create_account(public_key_bytes: bytes, forced_api_key: Optional[str] = None,
            db: Optional[sqlite3.Connection]=None) -> tuple[int, str]:
        assert db is not None and isinstance(db, sqlite3.Connection)
        ...
    ```

This is not required for reading functions as they should run generally run inline unless they
are long running, in which case they should be handed off to a worker thread.

"""


from __future__ import annotations
import logging
try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.10.0 builds and bundled version of 3.35.5.
    import sqlite3
import time
from typing import Any, cast, NamedTuple, Optional, Sequence

from electrumsv_database.sqlite import bulk_insert_returning, read_rows_by_id, \
    replace_db_context_with_connection

from .constants import AccountFlag, IndexerPushdataRegistrationFlag, OutboundDataFlag
from .types import AccountIndexerMetadata, OutboundDataLogRow, OutboundDataCreatedRow, \
    OutboundDataPendingRow, OutboundDataRow, TipFilterListEntry, TipFilterRegistrationEntry
from .utils import create_account_api_token

# Useful regexes for searching codebase:
# - create.*_table -> finds all table creation functions

logger = logging.getLogger("app-database")


APPLICATION_ID = int.from_bytes(b"ESVR", "big", signed=True)
LATEST_MIGRATION = 2


class AccountMetadata(NamedTuple):
    # The identity public key for this client.
    public_key_bytes: bytes
    # The active API key for this client.
    api_key: str
    flags: AccountFlag


class DatabaseStateModifiedError(Exception):
    # The database state was not as we required it to be in some way.
    pass


def setup(db: sqlite3.Connection) -> None:
    assert db is not None and isinstance(db, sqlite3.Connection)
    initialise_database(db)
    create_tables(db)
    clear_stale_state(db)

def create_tables(db: sqlite3.Connection) -> None:
    create_account_table(db)
    create_indexer_filtering_registrations_pushdata_table(db)
    create_outbound_data_table(db)
    create_outbound_data_logs_table(db)

    db.execute(f"PRAGMA user_version={LATEST_MIGRATION}")


def initialise_database(db: sqlite3.Connection) -> None:
    global APPLICATION_ID
    application_id = db.execute("PRAGMA application_id").fetchone()[0]
    if application_id == 0:
        db.execute(f"PRAGMA application_id={APPLICATION_ID}")
    else:
        assert application_id == APPLICATION_ID, "Not a recognised reference server database " \
            f"{application_id}!={APPLICATION_ID}"

    current_migration = db.execute("PRAGMA user_version").fetchone()[0]
    assert current_migration <= LATEST_MIGRATION
    if current_migration == 0:
        # We do not know if this is an existing database without a version (migration 1) or a
        # freshly created empty one (migration 0). Look if tables already exist to differentiate.
        cursor = db.execute("SELECT name FROM sqlite_schema "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        current_migration = 0 if len(cursor.fetchall()) == 0 else 1

    if current_migration == 1:
        # Motivation: We removed the requirement that a payment channel be created as part of the
        #     new account creation process.
        db.execute("DROP TABLE account_payment_channels")
        db.execute("ALTER TABLE accounts DROP COLUMN active_channel_id")
        db.execute("ALTER TABLE accounts DROP COLUMN last_payment_key_index")

def delete_all_tables(db: sqlite3.Connection) -> None:
    db.execute("DROP TABLE IF EXISTS outbound_data_logs")
    db.execute("DROP TABLE IF EXISTS outbound_data")
    db.execute("DROP TABLE IF EXISTS indexer_filtering_registrations_pushdata")
    db.execute("DROP TABLE IF EXISTS accounts")

def clear_stale_state(db: sqlite3.Connection) -> None:
    # Remove the non-finalised registrations that were perhaps interrupted by a crash.
    # May not ever happen, but cover the case where it does.
    prune_indexer_filtering(IndexerPushdataRegistrationFlag.NONE,
        IndexerPushdataRegistrationFlag.FINALISED, db=db)
    # Remove the finalised registrations that have expired.
    prune_indexer_filtering(IndexerPushdataRegistrationFlag.FINALISED,
        IndexerPushdataRegistrationFlag.FINALISED, int(time.time()), db=db)

# SECTION: Accounts

def create_account_table(db: sqlite3.Connection) -> None:
    """
        flags:                      ...
        public_key_bytes:           ...
        api_key:                    The active API key for the account.
        tip_filter_callback_url:    If there is a connected indexer service behind the reference
                                    server, the user can set the url and the token for any tip
                                    filter callbacks.
        tip_filter_callback_token:  The API key required for the reference server to post tip
                                    filter notifications to the given callback url.
    """
    sql = f"""
    CREATE TABLE IF NOT EXISTS accounts (
        account_id                      INTEGER     PRIMARY KEY,
        flags                           INTEGER     DEFAULT {AccountFlag.NONE},
        public_key_bytes                BINARY(32),
        api_key                         TEXT        NOT NULL,

        tip_filter_callback_url         TEXT        NULL,
        tip_filter_callback_token       TEXT        NULL,
        tip_filter_update_count         INTEGER     DEFAULT 0
    )
    """
    db.execute(sql)

    sql = """
    CREATE INDEX IF NOT EXISTS master_api_key_idx ON accounts (api_key);
    """
    db.execute(sql)

def create_account(public_key_bytes: bytes, db: Optional[sqlite3.Connection]=None) \
        -> tuple[int, str]:
    assert db is not None and isinstance(db, sqlite3.Connection)
    sql = """
    INSERT INTO accounts (public_key_bytes, api_key) VALUES (?, ?)
    """
    api_key = create_account_api_token()
    cursor = db.execute(sql, (public_key_bytes, api_key))
    # This should be set for INSERT and REPLACE operations.
    assert cursor.lastrowid is not None
    account_id: int = cursor.lastrowid
    return account_id, api_key

def deactivate_account(account_id: int, flags: AccountFlag,
        db: Optional[sqlite3.Connection]=None) -> None:
    assert db is not None and isinstance(db, sqlite3.Connection)
    sql = """
    UPDATE accounts SET flags=flags|? WHERE account_id=?
    """
    assert flags & AccountFlag.DISABLED_MASK != 0
    db.execute(sql, (flags, account_id))

@replace_db_context_with_connection
def get_account_id_for_api_key(db: sqlite3.Connection, api_key: str) \
        -> tuple[Optional[int], AccountFlag]:
    """
    This is not indicative of whether there is an account or not as disabled accounts will
    not be matched. If the account is valid, then and only then should the account id be
    returned.
    """
    sql = "SELECT account_id, flags FROM accounts WHERE api_key=?1 AND flags&?2=0"
    result = db.execute(sql, (api_key, AccountFlag.DISABLED_MASK)).fetchall()
    if len(result) == 0:
        return None, AccountFlag.NONE
    account_id: int
    account_flags: AccountFlag
    account_id, account_flags = result[0]
    return account_id, account_flags

@replace_db_context_with_connection
def get_account_id_for_public_key_bytes(db: sqlite3.Connection, public_key_bytes: bytes) \
        -> tuple[Optional[int], AccountFlag]:
    """
    If an account id is returned the caller should check the account flags before using
    that account id. An example of this is checking the DISABLED_MASK and not authorising
    the action if it is disabled.
    """
    sql = "SELECT account_id, flags FROM accounts WHERE public_key_bytes = ?1"
    result = db.execute(sql, (public_key_bytes,)).fetchall()
    if len(result) == 0:
        return None, AccountFlag.NONE
    account_id: int
    account_flags: AccountFlag
    account_id, account_flags = result[0]
    return account_id, account_flags

@replace_db_context_with_connection
def get_account_metadata_for_account_id(db: sqlite3.Connection, account_id: int) -> AccountMetadata:
    sql = "SELECT public_key_bytes, api_key, flags FROM accounts WHERE account_id = ?1"
    row = db.execute(sql, (account_id,)).fetchone()
    if row is None:
        return AccountMetadata(b'', '', AccountFlag.NONE)
    return AccountMetadata(*row)

# SECTION: Indexer-related

def create_indexer_filtering_registrations_pushdata_table(db: sqlite3.Connection) -> None:
    """
    Register pushdata hashes to be monitored by the indexer.
    """
    sql = """
    CREATE TABLE IF NOT EXISTS indexer_filtering_registrations_pushdata (
        account_id              INTEGER     NOT NULL,
        pushdata_hash           BINARY(32)  NOT NULL,
        flags                   INTEGER     NOT NULL,
        date_expires            INTEGER     NOT NULL,
        date_created            INTEGER     NOT NULL
    )
    """
    db.execute(sql)
    sql = """
    CREATE UNIQUE INDEX IF NOT EXISTS idx_indexer_filtering_pushdata
        ON indexer_filtering_registrations_pushdata(account_id, pushdata_hash)
    """
    db.execute(sql)

def create_indexer_filtering_registrations_pushdatas(account_id: int,
        registration_entries: list[TipFilterRegistrationEntry],
        db: Optional[sqlite3.Connection]=None) -> Optional[int]:
    assert db is not None and isinstance(db, sqlite3.Connection)
    # We use the SQLite `OR ABORT` clause to ensure we either insert all registrations or none
    # if some are already present. This means we do not need to rely on rolling back the
    # transaction because no changes should have been made in event of conflict.
    sql = """
    INSERT OR ABORT INTO indexer_filtering_registrations_pushdata
        (account_id, pushdata_hash, flags, date_created, date_expires) VALUES (?, ?, ?, ?, ?)
    """
    date_created = int(time.time())
    insert_rows: list[tuple[int, bytes, int, int, int]] = []
    for pushdata_value, duration_seconds in registration_entries:
        insert_rows.append((account_id, pushdata_value, 0, date_created,
            date_created + duration_seconds))
    try:
        db.executemany(sql, insert_rows)
    except sqlite3.IntegrityError:
        # No changes should have been made. Indicate that what was inserted was nothing.
        return None
    else:
        return date_created

@replace_db_context_with_connection
def read_indexer_filtering_registrations_pushdatas(db: sqlite3.Connection, account_id: int,
        # These defaults include all rows no matter the flag value.
        expected_flags: IndexerPushdataRegistrationFlag=IndexerPushdataRegistrationFlag.NONE,
        mask: IndexerPushdataRegistrationFlag=IndexerPushdataRegistrationFlag.NONE) \
            -> list[TipFilterListEntry]:
    sql = """
    SELECT pushdata_hash, date_created, date_expires FROM indexer_filtering_registrations_pushdata
    WHERE account_id=? AND flags&?=?
    """
    entries = list[TipFilterListEntry]()
    for row in db.execute(sql, (account_id, mask, expected_flags)).fetchall():
        entries.append(TipFilterListEntry(row[0], row[1], row[2] - row[1]))
    return entries

def update_indexer_filtering_registrations_pushdatas_flags(
        account_id: int,
        pushdata_hashes: list[bytes],
        update_flags: IndexerPushdataRegistrationFlag=IndexerPushdataRegistrationFlag.NONE,
        update_mask: Optional[IndexerPushdataRegistrationFlag]=None,
        filter_flags: IndexerPushdataRegistrationFlag=IndexerPushdataRegistrationFlag.NONE,
        filter_mask: Optional[IndexerPushdataRegistrationFlag]=None,
        require_all: bool=False,
        db: Optional[sqlite3.Connection]=None) -> None:
    assert db is not None and isinstance(db, sqlite3.Connection)
    # Ensure that the update only affects the update flags if no mask is provided.
    final_update_mask = ~update_flags if update_mask is None else update_mask
    # Ensure that the filter only looks at the filter flags if no mask is provided.
    final_filter_mask = filter_flags if filter_mask is None else filter_mask
    sql = """
    UPDATE indexer_filtering_registrations_pushdata
    SET flags=(flags&?)|?
    WHERE account_id=? AND pushdata_hash=? AND (flags&?)=?
    """
    update_rows: list[tuple[int, int, int, bytes, int, int]] = []
    for pushdata_hash in pushdata_hashes:
        update_rows.append((final_update_mask, update_flags, account_id, pushdata_hash,
            final_filter_mask, filter_flags))
    cursor = db.executemany(sql, update_rows)
    if require_all and cursor.rowcount != len(pushdata_hashes):
        raise DatabaseStateModifiedError

def delete_indexer_filtering_registrations_pushdatas(account_id: int,
        pushdata_hashes: list[bytes],
        # These defaults include all rows no matter the flag value.
        expected_flags: IndexerPushdataRegistrationFlag=IndexerPushdataRegistrationFlag.NONE,
        mask: IndexerPushdataRegistrationFlag=IndexerPushdataRegistrationFlag.NONE,
        db: Optional[sqlite3.Connection]=None) -> None:
    assert db is not None and isinstance(db, sqlite3.Connection)
    sql = """
    DELETE FROM indexer_filtering_registrations_pushdata
    WHERE account_id=? AND pushdata_hash=? AND flags&?=?
    """
    update_rows: list[tuple[int, bytes, int, int]] = []
    for pushdata_hash in pushdata_hashes:
        update_rows.append((account_id, pushdata_hash, mask, expected_flags))
    db.executemany(sql, update_rows)

def prune_indexer_filtering(expected_flags: IndexerPushdataRegistrationFlag,
        mask: IndexerPushdataRegistrationFlag, date_expires: Optional[int]=None,
        db: Optional[sqlite3.Connection]=None) -> int:
    assert db is not None and isinstance(db, sqlite3.Connection)
    sql = "DELETE FROM indexer_filtering_registrations_pushdata WHERE flags&?=?"
    sql_values: tuple[Any, ...] = (mask, expected_flags)
    if date_expires is not None:
        sql += " AND date_expires<=?"
        sql_values = (mask, expected_flags, date_expires)
    deletion_count = cast(int, db.execute(sql, sql_values).rowcount)
    logger.info("Pruned %d indexer filtering registrations", deletion_count)
    return deletion_count

@replace_db_context_with_connection
def read_account_indexer_metadata(db: sqlite3.Connection, account_ids: list[int]) \
        -> list[AccountIndexerMetadata]:
    sql = "SELECT account_id, tip_filter_callback_url, tip_filter_callback_token " \
        "FROM accounts WHERE account_id IN ({})"
    return read_rows_by_id(AccountIndexerMetadata, db, sql, [], account_ids)

def update_account_indexer_settings_write(account_id: int, settings: dict[str, Any],
        db: Optional[sqlite3.Connection]=None) -> dict[str, Any]:
    """
    This does partial updates depending on what is in `settings`.

    Raises DatabaseStateModifiedError
    """
    assert db is not None and isinstance(db, sqlite3.Connection)
    new_tip_filter_callback_url: Optional[str] = settings.get("tipFilterCallbackUrl", None)
    new_tip_filter_callback_token: Optional[str] = settings.get("tipFilterCallbackToken", None)
    sql_values: list[Any] = [ new_tip_filter_callback_url, new_tip_filter_callback_token,
        account_id ]
    sql = """
        UPDATE accounts SET tip_filter_callback_url=?, tip_filter_callback_token=?
        WHERE account_id=?
    """
    cursor = db.execute(sql, sql_values)
    if cursor.rowcount != 1:
        raise DatabaseStateModifiedError

    # All existing settings should be added to the "settings object" we return.
    return {
        "tipFilterCallbackUrl": new_tip_filter_callback_url,
        "tipFilterCallbackToken": new_tip_filter_callback_token,
    }

# SECTION: Outbound data.

def create_outbound_data_table(db: sqlite3.Connection) -> None:
    db.execute("""
    CREATE TABLE IF NOT EXISTS outbound_data (
        outbound_data_id        INTEGER     PRIMARY KEY,
        account_id              INTEGER     NOT NULL,
        outbound_data           BLOB        NOT NULL,
        outbound_data_hash      BLOB        NOT NULL,
        outbound_data_flags     INTEGER     NOT NULL,
        content_type            TEXT        NOT NULL,
        date_created            INTEGER     NOT NULL,
        FOREIGN KEY(account_id) REFERENCES accounts (account_id)
    )
    """)


def create_outbound_data_logs_table(db: sqlite3.Connection) -> None:
    db.execute("""
    CREATE TABLE IF NOT EXISTS outbound_data_logs (
        account_id              INTEGER     NOT NULL,
        outbound_data_id        INTEGER     DEFAULT NULL,
        outbound_data_flags     INTEGER     NOT NULL,
        response_status_code    INTEGER     DEFAULT NULL,
        response_reason         TEXT        DEFAULT NULL,
        date_created            INTEGER     NOT NULL,
        FOREIGN KEY(account_id) REFERENCES accounts (account_id),
        FOREIGN KEY(outbound_data_id) REFERENCES outbound_data (outbound_data_id)
    )
    """)


def create_outbound_datas_write(data_creation_rows: list[OutboundDataRow],
        log_creation_rows_by_key: dict[tuple[int, bytes], OutboundDataLogRow],
        db: Optional[sqlite3.Connection]=None) -> None:
    assert db is not None
    sql_prefix = "INSERT INTO outbound_data (outbound_data_id, account_id, outbound_data, " \
        "outbound_data_hash, outbound_data_flags, content_type, date_created) VALUES"
    sql_suffix = "RETURNING outbound_data_id, account_id, outbound_data_hash"
    # Remember that SQLite does not guarantee that the returned row order matches the insert order
    # so we need something to match the id to the inserted row, and the hash aids in this.
    datas_created = bulk_insert_returning(OutboundDataCreatedRow, db, sql_prefix, sql_suffix,
        data_creation_rows)
    if len(datas_created) != len(data_creation_rows):
        raise DatabaseStateModifiedError()

    # Insert all the created ids into the log rows.
    for data_created in datas_created:
        log_row_key = (data_created.account_id, data_created.outbound_data_hash)
        log_creation_rows_by_key[log_row_key] = log_creation_rows_by_key[log_row_key] \
            ._replace(outbound_data_id=data_created.outbound_data_id)

    log_creation_rows = list(log_creation_rows_by_key.values())
    # Verify that every log row got a created id for the outbound data row.
    assert all(log_row.outbound_data_id is not None for log_row in log_creation_rows)

    sql = "INSERT INTO outbound_data_logs (account_id, outbound_data_id, outbound_data_flags, " \
        "response_status_code, response_reason, date_created) VALUES (?, ?, ?, ?, ?, ?)"
    cursor = db.executemany(sql, log_creation_rows)
    if cursor.rowcount != len(log_creation_rows):
        raise DatabaseStateModifiedError()



def create_outbound_data_logs_write(creation_rows: list[OutboundDataLogRow],
        db: Optional[sqlite3.Connection]=None) -> None:
    assert db is not None
    sql = "INSERT INTO outbound_data_logs (account_id, outbound_data_id, outbound_data_flags, " \
        "response_status_code, response_reason, date_created) VALUES (?, ?, ?, ?, ?, ?)"
    cursor = db.executemany(sql, creation_rows)
    if cursor.rowcount != len(creation_rows):
        raise DatabaseStateModifiedError()


@replace_db_context_with_connection
def read_pending_outbound_datas(db: sqlite3.Connection, flags: OutboundDataFlag,
        mask: OutboundDataFlag) -> list[OutboundDataPendingRow]:
    sql = """
        WITH matches AS (
            SELECT outbound_data_id, date_created, row_number() OVER (PARTITION BY outbound_data_id
                ORDER BY date_created DESC) as rank
            FROM outbound_data_logs
            WHERE outbound_data_id IS NOT NULL
        )
        SELECT OD.outbound_data_id, OD.account_id, OD.outbound_data, OD.outbound_data_flags,
            OD.content_type, OD.date_created, A.tip_filter_callback_url, A.tip_filter_callback_token
        FROM outbound_data OD
        INNER JOIN matches M ON M.outbound_data_id=OD.outbound_data_id AND M.rank=1
        INNER JOIN accounts A ON A.account_id=OD.account_id
        WHERE (OD.outbound_data_flags&?)=?
        ORDER BY OD.date_created ASC
    """
    sql_values = (mask, flags)
    return [ OutboundDataPendingRow(row[0], row[1], row[2], OutboundDataFlag(row[3]), row[4],
        row[5], row[6], row[7]) for row in db.execute(sql, sql_values) ]


def update_outbound_data_flags_write(entries: list[tuple[OutboundDataFlag, int]],
        db: Optional[sqlite3.Connection]=None) -> None:
    assert db is not None
    sql = "UPDATE outbound_data SET outbound_data_flags=? WHERE outbound_data_id=?"
    cursor = db.executemany(sql, entries)
    assert cursor.rowcount == len(entries)


@replace_db_context_with_connection
def read_outbound_data_logs(db: sqlite3.Connection, outbound_data_ids: Sequence[int]) \
        -> list[OutboundDataLogRow]:
    sql = "SELECT account_id, outbound_data_id, outbound_data_flags, response_status_code, " \
        "response_reason, date_created FROM outbound_Data_logs WHERE outbound_data_id IN ({}) " \
        "ORDER BY date_created"
    return read_rows_by_id(OutboundDataLogRow, db, sql, [], outbound_data_ids)

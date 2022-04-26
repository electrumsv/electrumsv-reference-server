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
    import sqlite3  # type: ignore
import time
from typing import Any, cast, NamedTuple, Optional

from electrumsv_database.sqlite import read_rows_by_id, replace_db_context_with_connection

from .constants import AccountFlag, ChannelState, IndexerPushdataRegistrationFlag
from .types import AccountIndexerMetadata, TipFilterListEntry, TipFilterRegistrationEntry
from .utils import create_account_api_token

_ = """
Useful regexes for searching codebase:
- create.*_table -> finds all table creation functions
"""

logger = logging.getLogger("app-database")

class AccountMetadata(NamedTuple):
    # The identity public key for this client.
    public_key_bytes: bytes
    # The active API key for this client.
    api_key: str
    # This is the account funding payment channel for this account. It is possible we may later
    # want to have multiple payment channels for a given account, for different purposes.
    active_channel_id: Optional[int]
    flags: AccountFlag
    # For each payment channel the client opens with the server we increment this number.
    last_payment_key_index: int


class ChannelRow(NamedTuple):
    account_id: int
    channel_id: int
    channel_state: ChannelState
    # The key derivation information that tells us how to derive the payment key we gave the client.
    payment_key_index: int
    # The payment key we derived to give the client.
    payment_key_bytes: bytes
    # The hash of the funding transaction.
    funding_transaction_hash: Optional[bytes]
    # The funding output script from the funding transaction.
    funding_output_script_bytes: Optional[bytes]
    # How much the funding output value is in the funding transaction.
    funding_value: int
    client_payment_key_bytes: Optional[bytes]
    contract_transaction_bytes: Optional[bytes]
    refund_signature_bytes: Optional[bytes]
    # This is the latest refund amount based on updates from the client.
    refund_value: int
    # This is incremented with every updated refund amount from the client.
    refund_sequence: int
    # How much they have allocated from the funding to us.
    prepaid_balance_value: int
    # How much of the allocated funding they have "paid" to us.
    spent_balance_value: int


class DatabaseStateModifiedError(Exception):
    # The database state was not as we required it to be in some way.
    pass


def setup(db: sqlite3.Connection) -> None:
    assert db is not None and isinstance(db, sqlite3.Connection)
    create_tables(db)
    clear_stale_state(db)

def create_tables(db: sqlite3.Connection) -> None:
    create_account_table(db)
    create_account_payment_channel_table(db)
    create_indexer_filtering_registrations_pushdata_table(db)

def delete_all_tables(db: sqlite3.Connection) -> None:
    db.execute("DROP TABLE IF EXISTS indexer_filtering_registrations_pushdata")
    db.execute("DROP TABLE IF EXISTS account_payment_channels")
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
        active_channel_id:          ...
        last_payment_key_index:     The derivation index of the payment key given out to the
                                    user.
        api_key:                    The active API key for the account.
        tip_filter_callback_url:    If there is a connected indexer service behind the reference
                                    server, the user can set the url and the token for any tip
                                    filter callbacks.
        tip_filter_callback_token:  The API key required for the reference server to post tip
                                    filter notifications to the given callback url.
    """
    # TODO(1.4.0) Database. The `active_channel_id` should be a foreign key to the payment
    #     channels table. However I have repressed memories about the cross-foreign keys on
    #     both tables causing issues.
    sql = f"""
    CREATE TABLE IF NOT EXISTS accounts (
        account_id                      INTEGER     PRIMARY KEY,
        flags                           INTEGER     DEFAULT {AccountFlag.MID_CREATION},
        public_key_bytes                BINARY(32),
        active_channel_id               INTEGER     DEFAULT NULL,
        last_payment_key_index          INTEGER     DEFAULT 0,
        api_key                         TEXT        NOT NULL,

        tip_filter_callback_url         TEXT        NULL,
        tip_filter_callback_token       TEXT        NULL,
        tip_filter_update_count         INTEGER     DEFAULT 0
    )
    """
    db.execute(sql)

    sql = f"""
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
    sql = "SELECT account_id, flags FROM accounts WHERE api_key=? AND flags&?=0"
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
    sql = "SELECT account_id, flags FROM accounts WHERE public_key_bytes = ?"
    result = db.execute(sql, (public_key_bytes,)).fetchall()
    if len(result) == 0:
        return None, AccountFlag.NONE
    account_id: int
    account_flags: AccountFlag
    account_id, account_flags = result[0]
    return account_id, account_flags

@replace_db_context_with_connection
def get_account_metadata_for_account_id(db: sqlite3.Connection, account_id: int) -> AccountMetadata:
    sql = """
    SELECT public_key_bytes, api_key, active_channel_id, flags, last_payment_key_index
    FROM accounts WHERE account_id = ?
    """
    row = db.execute(sql, (account_id,)).fetchone()
    if row is None:
        return AccountMetadata(b'', '', None, AccountFlag.NONE, 0)
    return AccountMetadata(*row)

def set_account_registered(account_id: int, db: Optional[sqlite3.Connection]=None) -> None:
    assert db is not None and isinstance(db, sqlite3.Connection)
    sql = "UPDATE accounts SET flags=flags&? WHERE account_id=? AND flags&?=?"
    cursor = db.execute(sql, (~AccountFlag.MID_CREATION, AccountFlag.MID_CREATION,
        account_id, AccountFlag.MID_CREATION))
    if cursor.rowcount != 1:
        raise DatabaseStateModifiedError

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


# SECTION: Account payment channels

def create_account_payment_channel_table(db: sqlite3.Connection) -> None:
    #   refund_locktime         - Used to identify when the payment channel will close.
    sql = """
    CREATE TABLE IF NOT EXISTS account_payment_channels (
        channel_id                  INTEGER PRIMARY KEY,
        account_id                  INTEGER NOT NULL,
        channel_state               INTEGER NOT NULL,
        payment_key_index           INTEGER NOT NULL,
        payment_key_bytes           BINARY(32) NOT NULL,
        funding_value               INTEGER DEFAULT 0,
        refund_value                INTEGER DEFAULT 0,
        refund_locktime             INTEGER DEFAULT 0,
        refund_sequence             INTEGER DEFAULT 0,
        funding_transaction_bytes   BLOB DEFAULT NULL,
        funding_transaction_hash    BINARY(32) DEFAULT NULL,
        funding_output_script_bytes BLOB DEFAULT NULL,
        contract_transaction_bytes  BLOB DEFAULT NULL,
        refund_signature_bytes      BLOB DEFAULT NULL,
        client_payment_key_bytes    BINARY(32) DEFAULT NULL,
        prepaid_balance_value       INTEGER DEFAULT 0,
        spent_balance_value         INTEGER DEFAULT 0,
        date_created                INTEGER NOT NULL,

        FOREIGN KEY(account_id) REFERENCES accounts (account_id)
    )
    """
    db.execute(sql)

def create_account_payment_channel(account_id: int, payment_key_index: int,
        payment_key_bytes: bytes, db: Optional[sqlite3.Connection]=None) -> None:
    assert db is not None and isinstance(db, sqlite3.Connection)
    # It is expected the caller has already ruled out a payment channel already being in
    # place, and that this is dealt with before creating a new one.
    sql = """
    SELECT active_channel_id FROM accounts WHERE account_id=?
    """
    rows = db.execute(sql, (account_id,)).fetchall()
    assert len(rows) == 0 or rows[0][0] is None, rows

    channel_state = ChannelState.PAYMENT_KEY_DISPENSED
    sql = """
    INSERT INTO account_payment_channels (account_id, channel_state, payment_key_index,
        payment_key_bytes, date_created)
    VALUES (?, ?, ?, ?, ?)
    """
    date_created = int(time.time())
    cursor = db.execute(sql, (account_id, channel_state, payment_key_index, payment_key_bytes,
        date_created))
    # This should be set for INSERT and REPLACE operations.
    assert cursor.lastrowid is not None
    channel_id = cursor.lastrowid
    sql = """
    UPDATE accounts SET active_channel_id=?, last_payment_key_index=? WHERE account_id=?
    """
    db.execute(sql, (channel_id, payment_key_index, account_id))

def delete_account_payment_channel(channel_id: int, db: Optional[sqlite3.Connection]=None) -> None:
    assert db is not None and isinstance(db, sqlite3.Connection)
    sql = "DELETE FROM account_payment_channels WHERE channel_id=? RETURNING account_id"
    row = db.execute(sql, (channel_id,)).fetchone()
    if row is not None:
        account_id = row[0]
        sql = "UPDATE accounts SET active_channel_id=NULL " \
            "WHERE account_id=? AND active_channel_id=?"
        db.execute(sql, (account_id, channel_id)).fetchone()

@replace_db_context_with_connection
def get_active_channel_for_account_id(db: sqlite3.Connection, account_id: int) \
        -> Optional[ChannelRow]:
    sql = """
    SELECT APC.account_id, channel_id, channel_state, payment_key_index, payment_key_bytes,
        funding_transaction_hash, funding_output_script_bytes, funding_value,
        client_payment_key_bytes, contract_transaction_bytes, refund_signature_bytes,
        refund_value, refund_sequence, prepaid_balance_value, spent_balance_value
    FROM account_payment_channels APC
    INNER JOIN accounts A ON A.active_channel_id=APC.channel_id
    WHERE A.account_id=? AND A.active_channel_id IS NOT NULL
    """
    cursor = db.execute(sql, (account_id,))
    result = cursor.fetchall()
    if len(result) == 0:
        return None
    return ChannelRow(*result[0])

def set_payment_channel_initial_contract_transaction(channel_id: int,
        funding_value: int, funding_transaction_hash: bytes, refund_value: int,
        refund_signature_bytes: bytes, contract_transaction_bytes: bytes,
        client_payment_key_bytes: bytes, db: Optional[sqlite3.Connection]=None) -> None:
    """
    Raises DatabaseStateModifiedError
    """
    assert db is not None and isinstance(db, sqlite3.Connection)
    sql = """
    UPDATE account_payment_channels
    SET channel_state=?, funding_value=?, funding_transaction_hash=?, refund_value=?,
        refund_signature_bytes=?, contract_transaction_bytes=?, client_payment_key_bytes=?
    WHERE channel_id=? AND channel_state=?
    """
    cursor = db.execute(sql, (ChannelState.REFUND_ESTABLISHED, funding_value,
        funding_transaction_hash, refund_value, refund_signature_bytes,
        contract_transaction_bytes,
        client_payment_key_bytes, channel_id, ChannelState.PAYMENT_KEY_DISPENSED))
    if cursor.rowcount != 1:
        raise DatabaseStateModifiedError

def update_payment_channel_contract(channel_id: int, refund_value: int,
        refund_signature_bytes: bytes, refund_sequence: int,
        db: Optional[sqlite3.Connection]=None) -> None:
    """
    Raises DatabaseStateModifiedError
    """
    assert db is not None and isinstance(db, sqlite3.Connection)
    sql = """
    UPDATE account_payment_channels
    SET channel_state=?, refund_value=?, refund_signature_bytes=?, refund_sequence=?
    WHERE channel_id=? AND channel_state=?
    """
    cursor = db.execute(sql, (ChannelState.REFUND_ESTABLISHED, refund_value,
        refund_signature_bytes, refund_sequence, channel_id, ChannelState.CONTRACT_OPEN))
    if cursor.rowcount != 1:
        raise DatabaseStateModifiedError

def set_payment_channel_funding_transaction(channel_id: int,
        funding_transaction_bytes: bytes, funding_output_script_bytes: bytes,
        db: Optional[sqlite3.Connection]=None) -> None:
    """
    Raises DatabaseStateModifiedError
    """
    assert db is not None and isinstance(db, sqlite3.Connection)
    sql = """
    UPDATE account_payment_channels
    SET channel_state=?, funding_transaction_bytes=?, funding_output_script_bytes=?
    WHERE channel_id=? AND channel_state=?
    """
    cursor = db.execute(sql, (ChannelState.CONTRACT_OPEN, funding_transaction_bytes,
        funding_output_script_bytes, channel_id, ChannelState.REFUND_ESTABLISHED))
    if cursor.rowcount != 1:
        raise DatabaseStateModifiedError

def set_payment_channel_closed(channel_id: int, channel_state: ChannelState,
        db: Optional[sqlite3.Connection]=None) -> None:
    """
    Raises DatabaseStateModifiedError
    """
    assert db is not None and isinstance(db, sqlite3.Connection)
    sql = """
    UPDATE account_payment_channels SET channel_state=?
    WHERE channel_id=? AND channel_state<?
    """
    cursor = db.execute(sql, (channel_state, channel_id, ChannelState.CLOSED_MARKER))
    if cursor.rowcount != 1:
        raise DatabaseStateModifiedError

    sql = "UPDATE accounts SET active_channel_id=NULL WHERE active_channel_id=?"
    cursor = db.execute(sql, (channel_id,))
    if cursor.rowcount != 1:
        raise DatabaseStateModifiedError

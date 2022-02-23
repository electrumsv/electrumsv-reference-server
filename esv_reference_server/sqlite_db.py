"""
Copyright(c) 2021 Bitcoin Association.
Distributed under the Open BSV software license, see the accompanying file LICENSE

Much of this class and the connection pooling logic is inspired by and/or copied from the
ElectrumSV's wallet_database/sqlite_support.py and helps to avoid the overhead associated with
creating a new db connection
"""


from __future__ import annotations
import logging
import os
try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.10.0 builds and bundled version of 3.35.5.
    import sqlite3  # type: ignore
import time
from typing import NamedTuple, Optional

from electrumsv_database.sqlite import replace_db_context_with_connection

from .constants import AccountFlags, ChannelState, IndexerPushdataRegistrationFlag
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
    flags: AccountFlags
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
    pass


def setup(db: sqlite3.Connection) -> None:
    if int(os.getenv('REFERENCE_SERVER_RESET', "1")):
        delete_all_tables(db)
    create_tables(db)
    clear_leaked_state(db)

def create_tables(db: sqlite3.Connection) -> None:
    create_account_table(db)
    create_account_payment_channel_table(db)
    create_indexer_filtering_registrations_pushdata_table(db)

def delete_all_tables(db: sqlite3.Connection) -> None:
    sql = """SELECT name FROM sqlite_master WHERE type ='table' AND name NOT LIKE 'sqlite_%';"""
    table_names = [ row[0] for row in db.execute(sql).fetchall() ]

    for table_name in table_names:
        sql = f"DROP TABLE {table_name}"
        logger.debug("Running sql: %s", sql)
        db.execute(sql)

def clear_leaked_state(db: sqlite3.Connection) -> None:
    # Remove the non-finalised registrations that were perhaps interrupted by a crash.
    # May not ever happen, but cover the case where it does.
    prune_indexer_filtering(db, IndexerPushdataRegistrationFlag.NONE,
        IndexerPushdataRegistrationFlag.FINALISED)

# SECTION: Accounts

def create_account_table(db: sqlite3.Connection) -> None:
    sql = f"""
    CREATE TABLE IF NOT EXISTS accounts (
        account_id              INTEGER PRIMARY KEY,
        flags                   INTEGER DEFAULT {AccountFlags.MID_CREATION},
        public_key_bytes        BINARY(32),
        active_channel_id       INTEGER DEFAULT NULL,
        last_payment_key_index  INTEGER DEFAULT 0,
        api_key                 TEXT NOT NULL
    )
    """
    db.execute(sql)

    sql = f"""
    CREATE INDEX IF NOT EXISTS master_api_key_idx ON accounts (api_key);
    """
    db.execute(sql)

def create_account(db: sqlite3.Connection, public_key_bytes: bytes,
        forced_api_key: Optional[str] = None) -> tuple[int, str]:
    sql = """
    INSERT INTO accounts (public_key_bytes, api_key) VALUES (?, ?)
    """
    if forced_api_key:
        # Should only be used for REGTEST_VALID_ACCOUNT_TOKEN
        api_key = forced_api_key
    else:
        api_key = create_account_api_token()
    cursor = db.execute(sql, (public_key_bytes, api_key))
    # This should be set for INSERT and REPLACE operations.
    assert cursor.lastrowid is not None
    account_id: int = cursor.lastrowid
    return account_id, api_key

def deactivate_account(db: sqlite3.Connection, account_id: int, flags: AccountFlags) -> None:
    sql = """
    UPDATE accounts SET flags=flags|? WHERE account_id=?
    """
    assert flags & AccountFlags.DISABLED_MASK != 0
    db.execute(sql, (flags, account_id))

def get_account_id_for_api_key(db: sqlite3.Connection, api_key: str) \
        -> tuple[Optional[int], AccountFlags]:
    """
    This is not indicative of whether there is an account or not as disabled accounts will
    not be matched. If the account is valid, then and only then should the account id be
    returned.
    """
    sql = "SELECT account_id, flags FROM accounts WHERE api_key=? AND flags&?=0"
    result = db.execute(sql, (api_key, AccountFlags.DISABLED_MASK)).fetchall()
    if len(result) == 0:
        return None, AccountFlags.NONE
    account_id: int
    account_flags: AccountFlags
    account_id, account_flags = result[0]
    return account_id, account_flags

def get_account_id_for_public_key_bytes(db: sqlite3.Connection, public_key_bytes: bytes) \
        -> tuple[Optional[int], AccountFlags]:
    """
    If an account id is returned the caller should check the account flags before using
    that account id. An example of this is checking the DISABLED_MASK and not authorising
    the action if it is disabled.
    """
    sql = "SELECT account_id, flags FROM accounts WHERE public_key_bytes = ?"
    result = db.execute(sql, (public_key_bytes,)).fetchall()
    if len(result) == 0:
        return None, AccountFlags.NONE
    account_id: int
    account_flags: AccountFlags
    account_id, account_flags = result[0]
    return account_id, account_flags

def get_account_metadata_for_account_id(db: sqlite3.Connection, account_id: int) -> AccountMetadata:
    sql = """
    SELECT public_key_bytes, api_key, active_channel_id, flags, last_payment_key_index
    FROM accounts WHERE account_id = ?
    """
    result = db.execute(sql, (account_id,)).fetchall()
    if len(result) == 0:
        return AccountMetadata(b'', '', None, AccountFlags.NONE, 0)
    return AccountMetadata(*result[0])

def set_account_registered(db: sqlite3.Connection, account_id: int) -> None:
    sql = "UPDATE accounts SET flags=flags&? WHERE account_id=? AND flags&?=?"
    cursor = db.execute(sql, (~AccountFlags.MID_CREATION, AccountFlags.MID_CREATION,
        account_id, AccountFlags.MID_CREATION))
    if cursor.rowcount != 1:
        raise DatabaseStateModifiedError

# SECTION: Indexer-related

def create_indexer_filtering_registrations_pushdata_table(db: sqlite3.Connection) -> None:
    """
    Register pushdata hashes to be monitored by the indexer.
    """
    sql = """
    CREATE TABLE IF NOT EXISTS indexer_filtering_registrations_pushdata (
        account_id                  INTEGER NOT NULL,
        pushdata_hash               BINARY(32) NOT NULL,
        flags                       INTEGER NOT NULL DEFAULT 0,
        date_created                INTEGER NOT NULL,
        FOREIGN KEY(account_id) REFERENCES accounts (account_id)
    )
    """
    db.execute(sql)
    sql = """
    CREATE UNIQUE INDEX IF NOT EXISTS idx_indexer_filtering_pushdata
        ON indexer_filtering_registrations_pushdata(account_id, pushdata_hash)
    """
    db.execute(sql)

def create_indexer_filtering_registrations_pushdatas(db: sqlite3.Connection, account_id: int,
        pushdata_hashes: list[bytes]) -> list[bytes]:
    # It is expected the caller has already ruled out a payment channel already being in
    # place, and that this is dealt with before creating a new one.
    sql = """
    INSERT OR ABORT INTO indexer_filtering_registrations_pushdata
        (account_id, pushdata_hash, flags, date_created) VALUES (?, ?, ?, ?)
    """
    skip_flag = IndexerPushdataRegistrationFlag.FINALISED
    date_created = int(time.time())
    insert_rows: list[tuple[int, bytes, int, int]] = []
    for pushdata_value in pushdata_hashes:
        insert_rows.append((account_id, pushdata_value, 0, date_created))
    try:
        db.executemany(sql, insert_rows)
    except sqlite3.IntegrityError:
        # This will be existing unique conflict related rows that are present.
        return []

    # The `pysqlite` module is broken in the sense that you can only execute DML statements
    # with `executemany` which means that the bulk `INSERT` cannot do a `RETURNING` and we
    # need to do a second query to look this stuff up.
    sql = """
    SELECT pushdata_hash
    FROM indexer_filtering_registrations_pushdata
    WHERE account_id=? AND date_created=? AND flags&?=0
    """
    result_rows: list[tuple[bytes]] = \
        db.execute(sql, (account_id, date_created, skip_flag)).fetchall()
    # The results should be the registrations that were present and unfinalised or not present.
    return [ pushdata_value for (pushdata_value,) in result_rows ]

def finalise_indexer_filtering_registrations_pushdatas(db: sqlite3.Connection, account_id: int,
        pushdata_hashes: list[bytes]) -> None:
    sql = """
    UPDATE indexer_filtering_registrations_pushdata SET flags=flags|? WHERE account_id=? AND
        pushdata_hash=?
    """
    set_flag = IndexerPushdataRegistrationFlag.FINALISED
    update_rows: list[tuple[int, int, bytes]] = []
    for pushdata_value in pushdata_hashes:
        update_rows.append((set_flag, account_id, pushdata_value))
    db.executemany(sql, update_rows)

def delete_indexer_filtering_registrations_pushdatas(db: sqlite3.Connection, account_id: int,
        pushdata_hashes: list[bytes],
        # These defaults include all rows no matter the flag value.
        expected_flags: IndexerPushdataRegistrationFlag=IndexerPushdataRegistrationFlag.NONE,
        mask: IndexerPushdataRegistrationFlag=IndexerPushdataRegistrationFlag.NONE) -> None:
    sql = """
    DELETE FROM indexer_filtering_registrations_pushdata
    WHERE account_id=? AND pushdata_hash=? AND flags&?=?
    """
    update_rows: list[tuple[int, bytes, int, int]] = []
    for pushdata_value in pushdata_hashes:
        update_rows.append((account_id, pushdata_value, mask, expected_flags))
    db.executemany(sql, update_rows)

@replace_db_context_with_connection
def read_indexer_filtering_registrations_pushdatas(db: sqlite3.Connection, account_id: int,
        # These defaults include all rows no matter the flag value.
        expected_flags: IndexerPushdataRegistrationFlag=IndexerPushdataRegistrationFlag.NONE,
        mask: IndexerPushdataRegistrationFlag=IndexerPushdataRegistrationFlag.NONE) \
            -> list[bytes]:
    sql = """
    SELECT pushdata_hash FROM indexer_filtering_registrations_pushdata
    WHERE account_id=? AND flags&?=?
    """
    rows: list[tuple[bytes]] = db.execute(sql, (account_id, mask, expected_flags)).fetchall()
    return [ pushdata_hash for (pushdata_hash,) in rows ]

def prune_indexer_filtering(db: sqlite3.Connection, expected_flags: IndexerPushdataRegistrationFlag,
        mask: IndexerPushdataRegistrationFlag) -> None:
    db.execute("DELETE FROM indexer_filtering_registrations_pushdata WHERE flags&?=?",
        (mask, expected_flags))

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
        contract_transaction_bytes    BLOB DEFAULT NULL,
        refund_signature_bytes      BLOB DEFAULT NULL,
        client_payment_key_bytes    BINARY(32) DEFAULT NULL,
        prepaid_balance_value       INTEGER DEFAULT 0,
        spent_balance_value         INTEGER DEFAULT 0,
        date_created                INTEGER NOT NULL,
        FOREIGN KEY(account_id) REFERENCES accounts (account_id)
    )
    """
    db.execute(sql)

def create_account_payment_channel(db: sqlite3.Connection, account_id: int, payment_key_index: int,
        payment_key_bytes: bytes) -> None:
    # It is expected the caller has already ruled out a payment channel already being in
    # place, and that this is dealt with before creating a new one.
    sql = """
    SELECT active_channel_id FROM accounts WHERE account_id=?
    """
    rows = db.execute(sql, (account_id,)).fetchall()
    assert len(rows) == 0 or rows[0][0] is None

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

def delete_account_payment_channel(db: sqlite3.Connection, channel_id: int) -> None:
    sql = "DELETE FROM account_payment_channels WHERE channel_id=?"
    db.execute(sql, (channel_id,))

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

def set_payment_channel_initial_contract_transaction(db: sqlite3.Connection, channel_id: int,
        funding_value: int, funding_transaction_hash: bytes, refund_value: int,
        refund_signature_bytes: bytes, contract_transaction_bytes: bytes,
        client_payment_key_bytes: bytes) -> None:
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

def update_payment_channel_contract(db: sqlite3.Connection, channel_id: int, refund_value: int,
        refund_signature_bytes: bytes, refund_sequence: int) -> None:
    sql = """
    UPDATE account_payment_channels
    SET channel_state=?, refund_value=?, refund_signature_bytes=?, refund_sequence=?
    WHERE channel_id=? AND channel_state=?
    """
    cursor = db.execute(sql, (ChannelState.REFUND_ESTABLISHED, refund_value,
        refund_signature_bytes, refund_sequence, channel_id, ChannelState.CONTRACT_OPEN))
    if cursor.rowcount != 1:
        raise DatabaseStateModifiedError

def set_payment_channel_funding_transaction(db: sqlite3.Connection, channel_id: int,
        funding_transaction_bytes: bytes, funding_output_script_bytes: bytes) -> None:
    sql = """
    UPDATE account_payment_channels
    SET channel_state=?, funding_transaction_bytes=?, funding_output_script_bytes=?
    WHERE channel_id=? AND channel_state=?
    """
    cursor = db.execute(sql, (ChannelState.CONTRACT_OPEN, funding_transaction_bytes,
        funding_output_script_bytes, channel_id, ChannelState.REFUND_ESTABLISHED))
    if cursor.rowcount != 1:
        raise DatabaseStateModifiedError

def set_payment_channel_closed(db: sqlite3.Connection, channel_id: int,
        channel_state: ChannelState) -> None:
    """
    Raises DatabaseStateModifiedError
    """
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

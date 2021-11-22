"""Much of this class and the connection pooling logic is inspired by and/or copied from the
ElectrumSV's wallet_database/sqlite_support.py and helps to avoid the overhead associated with
creating a new db connection"""

from __future__ import annotations
import logging
import os
import queue
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Set, List, NamedTuple, Optional, Tuple

from .constants import AccountFlags, ChannelState


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


class LeakedSQLiteConnectionError(Exception):
    pass


def max_sql_variables() -> int:
    """Get the maximum number of arguments allowed in a query by the current
    sqlite3 implementation"""
    db = sqlite3.connect(':memory:')
    cur = db.cursor()
    cur.execute("CREATE TABLE t (test)")
    low, high = 0, 100000
    while (high - 1) > low:
        guess = (high + low) // 2
        query = 'INSERT INTO t VALUES ' + ','.join(['(?)' for _ in
                                                    range(guess)])
        args = [str(i) for i in range(guess)]
        try:
            cur.execute(query, args)
        except sqlite3.OperationalError as e:
            es = str(e)
            if "too many SQL variables" in es or "too many terms in compound SELECT" in es:
                high = guess
            else:
                raise
        else:
            low = guess
    cur.close()
    db.close()
    return low

# If the query deals with a list of values, then just batching using `SQLITE_MAX_VARS` should
# be enough. If it deals with expressions, then batch using the least of that and
# `SQLITE_EXPR_TREE_DEPTH`.
# - This shows how to estimate the maximum variables.
#   https://stackoverflow.com/a/36788489
# - This shows that even if you have higher maximum variables you get:
#   "Expression tree is too large (maximum depth 1000)"
#   https://github.com/electrumsv/electrumsv/issues/539
SQLITE_MAX_VARS = max_sql_variables()
SQLITE_EXPR_TREE_DEPTH = 1000


class SQLiteDatabase:
    """
    Due to connection pooling, all db operations (methods on this class) should be
    1) thread-safe
    2) low latency due to caching the connections prior to use
    """

    def __init__(self, storage_path: Path = Path('esv_reference_server.db')):
        self.logger = logging.getLogger("sqlite-database")
        self.storage_path = storage_path
        self.conn = sqlite3.connect(self.storage_path)
        self._db_path = str(storage_path)
        self._connection_pool: queue.Queue[sqlite3.Connection] = queue.Queue()
        self._active_connections: Set[sqlite3.Connection] = set()
        self.mined_tx_hashes_table_lock = threading.RLock()

        if int(os.getenv('REFERENCE_SERVER_RESET', "1")):
            self.reset_tables()
        else:  # create if not exist
            self.create_tables()

    def get_path(self) -> str:
        return self._db_path

    def acquire_connection(self) -> sqlite3.Connection:
        try:
            conn = self._connection_pool.get_nowait()
        except queue.Empty:
            self.increase_connection_pool()
            conn = self._connection_pool.get_nowait()
        self._active_connections.add(conn)
        return conn

    def release_connection(self, connection: sqlite3.Connection) -> None:
        self._active_connections.remove(connection)
        self._connection_pool.put(connection)

    def increase_connection_pool(self) -> None:
        """adds 1 more connection to the pool"""
        connection = sqlite3.connect(self._db_path, check_same_thread=False)
        self._connection_pool.put(connection)

    def decrease_connection_pool(self) -> None:
        """release 1 more connection from the pool - raises empty queue error"""
        connection = self._connection_pool.get_nowait()
        connection.close()

    def close(self) -> None:
        # Force close all outstanding connections
        outstanding_connections = list(self._active_connections)
        for conn in outstanding_connections:
            self.release_connection(conn)

        while self._connection_pool.qsize() > 0:
            self.decrease_connection_pool()

        leak_count = len(outstanding_connections)
        if leak_count:
            raise LeakedSQLiteConnectionError(f"Leaked {leak_count} SQLite connections "
                "when closing DatabaseContext.")
        assert self.is_closed()

    def is_closed(self) -> bool:
        return self._connection_pool.qsize() == 0

    def execute(self, sql: str, params: Optional[tuple]=None) -> List[Any]:
        """Thread-safe"""
        connection = self.acquire_connection()
        try:
            if not params:
                cur: sqlite3.Cursor = connection.execute(sql)
            else:
                cur: sqlite3.Cursor = connection.execute(sql, params)
            connection.commit()
            return cur.fetchall()
        except Exception:
            connection.rollback()
            self.logger.exception(f"An unexpected exception occured for SQL: {sql}")
            raise
        finally:
            self.release_connection(connection)

    def execute2(self, sql: str, params: Optional[tuple]=None) -> sqlite3.Cursor:
        """Thread-safe
        This returns the cursor to allow the caller to get rowcount or whatever.
        """
        connection = self.acquire_connection()
        try:
            if not params:
                cur: sqlite3.Cursor = connection.execute(sql)
            else:
                cur: sqlite3.Cursor = connection.execute(sql, params)
            connection.commit()
            return cur
        except Exception:
            connection.rollback()
            self.logger.exception(f"An unexpected exception occured for SQL: {sql}")
            raise
        finally:
            self.release_connection(connection)

    def create_tables(self):
        self.create_account_table()
        self.create_account_payment_channel_table()

    def drop_tables(self):
        self.drop_account_payment_channel_table()
        self.drop_account_table()

    def reset_tables(self):
        self.drop_tables()
        self.create_tables()

    # SECTION: Accounts

    def create_account_table(self) -> None:
        sql = f"""
        CREATE TABLE IF NOT EXISTS accounts (
            account_id              INTEGER PRIMARY KEY,
            flags                   INTEGER DEFAULT {AccountFlags.MID_CREATION},
            public_key_bytes        BINARY(32),
            active_channel_id       INTEGER DEFAULT NULL,
            last_payment_key_index  INTEGER DEFAULT 0,
            api_key                 TEXT DEFAULT NULL
        )
        """
        self.execute(sql)

    def drop_account_table(self) -> None:
        sql = "DROP TABLE IF EXISTS accounts"
        self.execute(sql)

    def create_account(self, public_key_bytes: bytes) -> Tuple[int, str]:
        sql = """
        INSERT INTO accounts (public_key_bytes, api_key) VALUES (?, ?)
        """
        api_key = os.urandom(32).hex()
        cursor = self.execute2(sql, (public_key_bytes, api_key))
        # This should be set for INSERT and REPLACE operations.
        assert cursor.lastrowid is not None
        account_id: int = cursor.lastrowid
        return account_id, api_key

    def deactivate_account(self, account_id: int, flags: AccountFlags) -> None:
        sql = """
        UPDATE accounts SET flags=flags|? WHERE account_id=?
        """
        assert flags & AccountFlags.DISABLED_MASK != 0
        self.execute2(sql, (flags, account_id))

    def get_account_id_for_api_key(self, api_key: str) -> Tuple[Optional[int], AccountFlags]:
        """
        This is not indicative of whether there is an account or not as disabled accounts will
        not be matched. If the account is valid, then and only then should the account id be
        returned.
        """
        sql = "SELECT account_id, flags FROM accounts WHERE api_key=? AND flags&?=0"
        result = self.execute(sql, params=(api_key, AccountFlags.DISABLED_MASK))
        if len(result) == 0:
            return None, AccountFlags.NONE
        account_id: int
        account_flags: AccountFlags
        account_id, account_flags = result[0]
        return account_id, account_flags

    def get_account_id_for_public_key_bytes(self, public_key_bytes: bytes) \
            -> Tuple[Optional[int], AccountFlags]:
        """
        If an account id is returned the caller should check the account flags before using
        that account id. An example of this is checking the DISABLED_MASK and not authorising
        the action if it is disabled.
        """
        sql = "SELECT account_id, flags FROM accounts WHERE public_key_bytes = ?"
        result = self.execute(sql, params=(public_key_bytes,))
        if len(result) == 0:
            return None, AccountFlags.NONE
        account_id: int
        account_flags: AccountFlags
        account_id, account_flags = result[0]
        return account_id, account_flags

    def get_account_metadata_for_account_id(self, account_id: int) -> AccountMetadata:
        sql = """
        SELECT public_key_bytes, api_key, active_channel_id, flags, last_payment_key_index
        FROM accounts WHERE account_id = ?
        """
        result = self.execute(sql, params=(account_id,))
        if len(result) == 0:
            return AccountMetadata(b'', '', None, AccountFlags.NONE, 0)
        return AccountMetadata(*result[0])

    def set_account_registered(self, account_id: int) -> None:
        sql = "UPDATE accounts SET flags=flags&? WHERE account_id=? AND flags&?=?"
        cursor = self.execute2(sql, (~AccountFlags.MID_CREATION, AccountFlags.MID_CREATION,
            account_id, AccountFlags.MID_CREATION))
        if cursor.rowcount != 1:
            raise DatabaseStateModifiedError

    # SECTION: Account payment channels

    def create_account_payment_channel_table(self) -> None:
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
        self.execute(sql)

    def drop_account_payment_channel_table(self) -> None:
        sql = "DROP TABLE IF EXISTS account_payment_channels"
        self.execute(sql)

    def create_account_payment_channel(self, account_id: int, payment_key_index: int,
            payment_key_bytes: bytes) -> None:
        # It is expected the caller has already ruled out a payment channel already being in
        # place, and that this is dealt with before creating a new one.
        sql = """
        SELECT active_channel_id FROM accounts WHERE account_id=?
        """
        rows = self.execute(sql, (account_id,))
        assert len(rows) == 0 or rows[0][0] is None

        channel_state = ChannelState.PAYMENT_KEY_DISPENSED
        sql = """
        INSERT INTO account_payment_channels (account_id, channel_state, payment_key_index,
            payment_key_bytes, date_created)
        VALUES (?, ?, ?, ?, ?)
        """
        date_created = int(time.time())
        cursor = self.execute2(sql, (account_id, channel_state, payment_key_index,
            payment_key_bytes, date_created))
        # This should be set for INSERT and REPLACE operations.
        assert cursor.lastrowid is not None
        channel_id = cursor.lastrowid
        sql = """
        UPDATE accounts SET active_channel_id=?, last_payment_key_index=? WHERE account_id=?
        """
        self.execute(sql, (channel_id, payment_key_index, account_id))

    def delete_account_payment_channel(self, channel_id: int) -> None:
        sql = "DELETE FROM account_payment_channels WHERE channel_id=?"
        self.execute(sql, (channel_id,))

    def get_active_channel_for_account_id(self, account_id: int) -> Optional[ChannelRow]:
        sql = """
        SELECT APC.account_id, channel_id, channel_state, payment_key_index, payment_key_bytes,
            funding_transaction_hash, funding_output_script_bytes, funding_value,
            client_payment_key_bytes, contract_transaction_bytes, refund_signature_bytes,
            refund_value, refund_sequence, prepaid_balance_value, spent_balance_value
        FROM account_payment_channels APC
        INNER JOIN accounts A ON A.active_channel_id=APC.channel_id
        WHERE A.account_id=? AND A.active_channel_id IS NOT NULL
        """
        result = self.execute(sql, params=(account_id,))
        if len(result) == 0:
            return None
        return ChannelRow(*result[0])

    def set_payment_channel_initial_contract_transaction(self, channel_id: int, funding_value: int,
            funding_transaction_hash: bytes, refund_value: int, refund_signature_bytes: bytes,
            contract_transaction_bytes: bytes, client_payment_key_bytes: bytes) -> None:
        sql = """
        UPDATE account_payment_channels
        SET channel_state=?, funding_value=?, funding_transaction_hash=?, refund_value=?,
            refund_signature_bytes=?, contract_transaction_bytes=?, client_payment_key_bytes=?
        WHERE channel_id=? AND channel_state=?
        """
        cursor = self.execute2(sql, (ChannelState.REFUND_ESTABLISHED, funding_value,
            funding_transaction_hash, refund_value, refund_signature_bytes,
            contract_transaction_bytes,
            client_payment_key_bytes, channel_id, ChannelState.PAYMENT_KEY_DISPENSED))
        if cursor.rowcount != 1:
            raise DatabaseStateModifiedError

    def update_payment_channel_contract(self, channel_id: int, refund_value: int,
            refund_signature_bytes: bytes, refund_sequence: int) -> None:
        sql = """
        UPDATE account_payment_channels
        SET channel_state=?, refund_value=?, refund_signature_bytes=?, refund_sequence=?
        WHERE channel_id=? AND channel_state=?
        """
        cursor = self.execute2(sql, (ChannelState.REFUND_ESTABLISHED, refund_value,
            refund_signature_bytes, refund_sequence, channel_id, ChannelState.CONTRACT_OPEN))
        if cursor.rowcount != 1:
            raise DatabaseStateModifiedError

    def set_payment_channel_funding_transaction(self, channel_id: int,
            funding_transaction_bytes: bytes, funding_output_script_bytes: bytes) -> None:
        sql = """
        UPDATE account_payment_channels
        SET channel_state=?, funding_transaction_bytes=?, funding_output_script_bytes=?
        WHERE channel_id=? AND channel_state=?
        """
        cursor = self.execute2(sql, (ChannelState.CONTRACT_OPEN, funding_transaction_bytes,
            funding_output_script_bytes, channel_id, ChannelState.REFUND_ESTABLISHED))
        if cursor.rowcount != 1:
            raise DatabaseStateModifiedError

    def set_payment_channel_closed(self, channel_id: int, channel_state: ChannelState) -> None:
        """

        Raises DatabaseStateModifiedError
        """
        sql = """
        UPDATE account_payment_channels SET channel_state=?
        WHERE channel_id=? AND channel_state<?
        """
        cursor = self.execute2(sql, (channel_state, channel_id, ChannelState.CLOSED_MARKER))
        if cursor.rowcount != 1:
            raise DatabaseStateModifiedError

        sql = "UPDATE accounts SET active_channel_id=NULL WHERE active_channel_id=?"
        cursor = self.execute2(sql, (channel_id,))
        if cursor.rowcount != 1:
            raise DatabaseStateModifiedError

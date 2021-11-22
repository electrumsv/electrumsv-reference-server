"""Much of this class and the connection pooling logic is inspired by and/or copied from the
ElectrumSV's wallet_database/sqlite_support.py and helps to avoid the overhead associated with
creating a new db connection"""

from __future__ import annotations
import logging
import os
import queue
import sqlite3
import threading
from pathlib import Path
from typing import Set, List, Optional, Tuple

from bitcoinx import hash_to_hex_str, hex_str_to_hash

from esv_reference_server.types import PeerChannelAccountRow


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

    def execute(self, sql: str, params: Optional[tuple]=None) -> List:
        """Thread-safe"""
        connection = self.acquire_connection()
        try:
            if not params:
                cur: sqlite3.Cursor = connection.execute(sql)
            else:
                cur: sqlite3.Cursor = connection.execute(sql, params)
            connection.commit()
            return cur.fetchall()
        except sqlite3.IntegrityError as e:
            if str(e).find('UNIQUE constraint failed') != -1:
                pass
                # self.logger.debug(f"caught unique constraint violation "
                #                   f"- skipped redundant insertion")
                # self.logger.debug(f"caught unique constraint violation: {sql} "
                #                   f"- skipped redundant insertion")
        except Exception:
            connection.rollback()
            self.logger.exception(f"An unexpected exception occured for SQL: {sql}")
        finally:
            self.release_connection(connection)

    def create_tables(self):
        self.create_account_table()
        self.create_peer_channel_accounts_table()

    def drop_tables(self):
        self.drop_account_table()
        self.drop_peer_channel_accounts_table()

    def reset_tables(self):
        self.drop_tables()
        self.create_tables()

    def create_account_table(self) -> None:
        sql = (
            """
            CREATE TABLE IF NOT EXISTS accounts (
                account_id          INTEGER,
                public_key_bytes    BINARY(32),
                api_key             TEXT
            )"""
        )
        self.execute(sql)

    def drop_account_table(self) -> None:
        sql = (
            """DROP TABLE IF EXISTS accounts"""
        )
        self.execute(sql)

    def create_peer_channel_accounts_table(self) -> None:
        sql = (
            """
            CREATE TABLE IF NOT EXISTS peer_channel_accounts (
                peer_channel_account_id  INTEGER,
                peer_channel_account_name VARCHAR(256),
                peer_channel_username    VARCHAR(256),
                peer_channel_password    VARCHAR(1024),
                account_id  INTEGER,
                FOREIGN KEY(account_id) REFERENCES accounts(account_id)
            )"""
        )
        self.execute(sql)

    def create_channels_table(self) -> None:
        """
        peer_channel_account_id:  is needed to proxy the request to backend
                                   the PeerChannel instance
        account_id:  is needed for pro-rata billing to the payment channel
                     account
        channel_id & channel_bearer_token:  random 64 byte base64.urlsafe fields
                                            assigned when a new channel is created
        """
        sql = (
            """
            CREATE TABLE IF NOT EXISTS channels (
                channel_id VARCHAR(256) PRIMARY KEY,
                channel_bearer_token VARCHAR(256),
                peer_channel_account_id INTEGER,
                account_id  INTEGER,
                FOREIGN KEY (peer_channel_account_id) REFERENCES peer_channel_accounts(account_id),
                FOREIGN KEY(account_id) REFERENCES accounts(account_id)
            )"""
        )
        self.execute(sql)

    def drop_peer_channel_accounts_table(self) -> None:
        sql = (
            """DROP TABLE IF EXISTS peer_channel_accounts"""
        )
        self.execute(sql)

    def insert_peer_channel_account(self, account_row: PeerChannelAccountRow):
        sql = """INSERT INTO peer_channel_accounts VALUES(?,?,?,?,?)"""
        self.execute(sql, params=account_row)

    def get_account_id_for_api_key(self, api_key: str) -> Optional[int]:
        sql = "SELECT account_id FROM accounts WHERE api_key = ?"
        result = self.execute(sql, params=(api_key,))
        if len(result) == 0:
            return None
        account_id: int = result[0][0]
        return account_id

    def get_account_id_for_public_key_bytes(self, public_key_bytes: bytes) -> Optional[int]:
        sql = "SELECT account_id FROM accounts WHERE public_key_bytes = ?"
        result = self.execute(sql, params=(public_key_bytes,))
        if len(result) == 0:
            return None
        account_id: int = result[0][0]
        return account_id

    def get_account_metadata_for_account_id(self, account_id: int) -> Tuple[bytes, str]:
        sql = "SELECT public_key_bytes, api_key FROM accounts WHERE account_id = ?"
        result = self.execute(sql, params=(account_id,))
        if len(result) == 0:
            return b'', ''
        return result[0]

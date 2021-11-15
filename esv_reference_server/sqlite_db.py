"""Much of this class and the connection pooling logic is inspired by and/or copied from the
ElectrumSV's wallet_database/sqlite_support.py and helps to avoid the overhead associated with
creating a new db connection"""

import logging
import os
import queue
import sqlite3
import threading
from pathlib import Path
from typing import Set, List, Optional

from bitcoinx import hash_to_hex_str, hex_str_to_hash


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
        pass

    def drop_tables(self):
        pass

    def reset_tables(self):
        self.drop_tables()
        self.create_tables()

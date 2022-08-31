"""
Copyright(c) 2021 Bitcoin Association.
Distributed under the Open BSV software license, see the accompanying file LICENSE
"""
from __future__ import annotations

import time
from dataclasses import asdict
import logging

try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.10.0 builds and bundled version of 3.35.5.
    import sqlite3  # type: ignore
from typing import Any, cast, Optional, Union
from datetime import datetime, timezone

from electrumsv_database.sqlite import DatabaseContext, replace_db_context_with_connection

from .. import utils
from ..errors import APIErrors
from . import models, view_models
from .models import MsgBox, MsgBoxAPIToken, MessageMetadata, Message
from .view_models import APITokenViewModelGet, MessageViewModelGetJSON, \
    MessageViewModelGetBinary, MsgBoxViewModelAmend, MessageViewModelGet


class PeerChannelMessageWriteError(Exception):

    def __init__(self, code: APIErrors):
        self.code = code


class MsgBoxSQLiteRepository:

    def __init__(self, database_context: DatabaseContext) -> None:
        self.logger = logging.getLogger("msg-box-sqlite-db")
        self._database_context = database_context

    def create_tables(self, db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
        self.create_message_box_table(db)
        self.create_messages_table(db)
        self.create_message_box_api_tokens_table(db)
        self.create_message_status_table(db)

    def drop_tables(self, db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.execute("DROP TABLE IF EXISTS message_status")
        db.execute("DROP TABLE IF EXISTS msg_box_api_token")
        db.execute("DROP TABLE IF EXISTS message")
        db.execute("DROP TABLE IF EXISTS msg_box")

    def create_message_box_table(self, db: sqlite3.Connection) -> None:
        """Modelled very closely on Peer Channels reference implementation:
        https://github.com/electrumsv/spvchannels-reference"""
        sql = ("""
            CREATE TABLE IF NOT EXISTS msg_box (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id    BIGINT             NOT NULL,
                externalid    VARCHAR(1024)      NOT NULL,
                publicread    INTEGER,
                publicwrite   INTEGER,
                locked        INTEGER,
                sequenced     INTEGER,
                minagedays    INTEGER,
                maxagedays    INTEGER,
                autoprune     INTEGER,

                UNIQUE (externalid),
                FOREIGN KEY(account_id) REFERENCES accounts(account_id)

            )""")
        db.execute(sql)

    def create_messages_table(self, db: sqlite3.Connection) -> None:
        """Modelled very closely on Peer Channels reference implementation:
        https://github.com/electrumsv/spvchannels-reference"""

        sql = ("""
            CREATE TABLE IF NOT EXISTS message (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                fromtoken     BIGINT             NOT NULL,
                msg_box_id    BIGINT             NOT NULL,

                seq           BIGINT             NOT NULL,
                receivedts    INTEGER            NOT NULL,
                contenttype   VARCHAR(64)        NOT NULL,
                payload       BLOB,

                UNIQUE (msg_box_id, seq),
                FOREIGN KEY (fromtoken) REFERENCES msg_box_api_token (id),
                FOREIGN KEY (msg_box_id) REFERENCES msg_box (id)
            )""")
        db.execute(sql)

    def create_message_status_table(self, db: sqlite3.Connection) -> None:
        """Modelled very closely on Peer Channels reference implementation:
        https://github.com/electrumsv/spvchannels-reference"""
        sql = ("""
            CREATE TABLE IF NOT EXISTS message_status (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id    BIGINT             NOT NULL,
                token_id      BIGINT             NOT NULL,

                isread        INTEGER            NOT NULL,
                isdeleted     INTEGER            NOT NULL,

                FOREIGN KEY (message_id) REFERENCES message (id),
                FOREIGN KEY (token_id) REFERENCES msg_box_api_token (id)
            )""")
        db.execute(sql)

    def create_message_box_api_tokens_table(self, db: sqlite3.Connection) -> None:
        """Modelled very closely on Peer Channels reference implementation:
        https://github.com/electrumsv/spvchannels-reference"""

        sql = ("""CREATE TABLE IF NOT EXISTS msg_box_api_token (
              id                    INTEGER PRIMARY KEY AUTOINCREMENT,
              account_id            BIGINT             NOT NULL,
              msg_box_id            BIGINT             NOT NULL,

              token		            VARCHAR(1024),
              description           VARCHAR(1024),
              canread               INTEGER,
              canwrite              INTEGER,
              validfrom             INTEGER            NOT NULL,
              validto               INTEGER,

              UNIQUE (token),
              FOREIGN KEY (account_id) REFERENCES accounts (account_id),
              FOREIGN KEY (msg_box_id) REFERENCES msg_box (id)
            )
            """)
        db.execute(sql)

    def update_msg_box(self, msg_box_view_amend: MsgBoxViewModelAmend,
            external_id: str) -> Optional[view_models.MsgBoxViewModelAmend]:
        def write(db: Optional[sqlite3.Connection]=None) -> int:
            assert db is not None and isinstance(db, sqlite3.Connection)
            sql = """
                UPDATE msg_box
                SET  publicread= @publicread, publicwrite= @publicwrite, locked= @locked
                WHERE externalid= @externalid
                RETURNING id;
            """
            cursor = db.execute(sql, (msg_box_view_amend.public_read,
                msg_box_view_amend.public_write, msg_box_view_amend.locked, external_id))
            return len(cursor.fetchall())

        if not self._database_context.run_in_thread(write):
            return None

        return msg_box_view_amend

    def create_message_box(self, msg_box_view_create: view_models.MsgBoxViewModelCreate,
            account_id: int) -> MsgBox:
        msg_box_row = models.MsgBoxRow(
            account_id=account_id,
            locked=False,
            externalid=utils.create_external_id(),
            publicread=msg_box_view_create.public_read,
            publicwrite=msg_box_view_create.public_write,
            sequenced=msg_box_view_create.sequenced,
            minagedays=msg_box_view_create.retention.min_age_days,
            maxagedays=msg_box_view_create.retention.max_age_days,
            autoprune=msg_box_view_create.retention.auto_prune,
        )
        def write(db: Optional[sqlite3.Connection]=None) -> MsgBox:
            assert db is not None and isinstance(db, sqlite3.Connection)
            sql = """
                INSERT INTO msg_box (account_id, externalid, publicread, publicwrite, locked,
                    sequenced, minagedays, maxagedays, autoprune)
                VALUES(@owner, @externalid, @publicread, @publicwrite, @locked,
                    @sequenced, @minagedays, @maxagedays, @autoprune)
                RETURNING *;
            """
            cursor = db.execute(sql, msg_box_row)
            id, account_id, externalid, publicread, \
                publicwrite, locked, sequenced, \
                minagedays, maxagedays, autoprune = cursor.fetchone()

            msg_box_api_token_row = models.MsgBoxAPITokenRow(
                account_id=account_id,
                msg_box_id=id,
                token=utils.create_channel_api_token(),
                description="Owner",
                canread=True,
                canwrite=True,
                validfrom=int(time.time()),
                validto=None)
            cursor = self.create_msg_box_api_token(db, msg_box_api_token_row)
            id, account_id, msg_box_id, token, description, \
                canread, canwrite, validfrom, validto = cursor.fetchone()

            new_api_token = MsgBoxAPIToken(
                id=id,
                account_id=account_id,
                msg_box_id=msg_box_id,
                token=token,
                description=description,
                can_read=bool(canread),
                can_write=bool(canwrite),
                valid_from=validfrom,
                valid_to=validto)
            msg_box = MsgBox(id=id, account_id=account_id, external_id=externalid,
                public_read=publicread, public_write=publicwrite, locked=locked,
                sequenced=sequenced, min_age_days=minagedays, max_age_days=maxagedays,
                autoprune=autoprune, api_tokens=[new_api_token], head_message_sequence=0)
            return msg_box
        return self._database_context.run_in_thread(write)

    def create_msg_box_api_token(self, db: sqlite3.Connection,
            msg_box_api_token_row: models.MsgBoxAPITokenRow) -> sqlite3.Cursor:
        sql = """
            INSERT INTO msg_box_api_token (account_id, msg_box_id, token, description, canread,
                canwrite, validfrom)
            VALUES(@account_id, @msg_box_id, @token, @description, @canread, @canwrite, @validfrom)
            RETURNING *;
        """
        account_id, msg_box_externalid, token, description, canread, canwrite, validfrom, \
            validto = msg_box_api_token_row
        return db.execute(sql, (account_id, msg_box_externalid, token, description, canread,
                                 canwrite, validfrom))

    def get_msg_box_tokens(self, msg_box_id: int) -> list[MsgBoxAPIToken]:
        sql = "SELECT * FROM msg_box_api_token WHERE msg_box_id = ?"
        @replace_db_context_with_connection
        def read(db: sqlite3.Connection) -> list[MsgBoxAPIToken]:
            rows = db.execute(sql, (msg_box_id,)).fetchall()
            msg_box_api_tokens = []

            id: int
            account_id: int
            msg_box_externalid: str
            token: str
            description: str
            canread: bool
            canwrite: bool
            validfrom: datetime
            validto: datetime
            for row in rows:
                id, account_id, msg_box_externalid, token, \
                    description, canread, canwrite, validfrom, validto = row
                msg_api_token = MsgBoxAPIToken(id=id, account_id=account_id, msg_box_id=msg_box_id,
                    token=token, description=description, can_read=canread, can_write=canwrite,
                    valid_from=validfrom, valid_to=validto)
                msg_box_api_tokens.append(msg_api_token)
            return msg_box_api_tokens
        return read(self._database_context)

    def get_message_box_by_id(self, message_box_id: int) -> Optional[MsgBox]:
        sql = """
            SELECT id, account_id, externalid, publicread, publicwrite, locked, sequenced,
                   minagedays, maxagedays, autoprune,
                   (SELECT max(seq) FROM message WHERE msg_box.id = message.msg_box_id) AS seq
            FROM msg_box
            WHERE id = @message_box_id
        """
        @replace_db_context_with_connection
        def read(db: sqlite3.Connection) -> Optional[MsgBox]:
            nonlocal message_box_id
            row = db.execute(sql, (message_box_id,)).fetchone()
            if row is None:
                return None

            id, account_id, externalid, publicread, publicwrite, locked, \
                sequenced, minagedays, maxagedays, autoprune, head_message_sequence = row
            msg_box_api_tokens = self.get_msg_box_tokens(id)
            head_message_sequence = head_message_sequence if head_message_sequence else 0

            return MsgBox(id=id, account_id=account_id, external_id=externalid,
                public_read=publicread, public_write=publicwrite, locked=locked,
                sequenced=sequenced, min_age_days=minagedays, max_age_days=maxagedays,
                autoprune=autoprune, api_tokens=msg_box_api_tokens,
                head_message_sequence=head_message_sequence)

        return read(self._database_context)

    def get_msg_box(self, account_id: int, externalid: str) -> Optional[MsgBox]:
        sql = """
            SELECT id, account_id, externalid, publicread, publicwrite, locked, sequenced,
                   minagedays, maxagedays, autoprune,
                   (SELECT max(seq) FROM message WHERE msg_box.id = message.msg_box_id) AS seq
            FROM msg_box
            WHERE account_id = @account_id AND externalid = @externalid
        """
        @replace_db_context_with_connection
        def read(db: sqlite3.Connection) -> Optional[MsgBox]:
            nonlocal account_id, externalid
            rows = db.execute(sql, (account_id, externalid)).fetchall()
            if len(rows) == 0:
                return None

            id, account_id, externalid, publicread, publicwrite, locked, \
                sequenced, minagedays, maxagedays, autoprune, head_message_sequence = rows[0]
            msg_box_api_tokens = self.get_msg_box_tokens(id)
            head_message_sequence = head_message_sequence if head_message_sequence else 0

            return MsgBox(id=id, account_id=account_id, external_id=externalid,
                public_read=publicread, public_write=publicwrite, locked=locked,
                sequenced=sequenced, min_age_days=minagedays, max_age_days=maxagedays,
                autoprune=autoprune, api_tokens=msg_box_api_tokens,
                head_message_sequence=head_message_sequence)

        return read(self._database_context)

    def get_msg_boxes(self, account_id: int) -> list[MsgBox]:
        sql = """
            SELECT id, account_id, externalid, publicread, publicwrite, locked, sequenced,
                   minagedays, maxagedays, autoprune,
                   (SELECT max(seq) FROM message WHERE msg_box.id = message.msg_box_id) AS seq
            FROM msg_box
            WHERE account_id = @account_id;
        """
        @replace_db_context_with_connection
        def read(db: sqlite3.Connection) -> list[MsgBox]:
            nonlocal account_id
            rows = db.execute(sql, (account_id,)).fetchall()

            msg_boxes = []
            for row in rows:
                id, account_id, externalid, publicread, publicwrite, \
                    locked, sequenced, minagedays, maxagedays, autoprune, \
                    head_message_sequence = row
                msg_box_api_tokens = self.get_msg_box_tokens(id)
                head_message_sequence = head_message_sequence if head_message_sequence else 0

                msg_box = MsgBox(id=id, account_id=account_id, external_id=externalid,
                    public_read=publicread, public_write=publicwrite, locked=locked,
                    sequenced=sequenced, min_age_days=minagedays, max_age_days=maxagedays,
                    autoprune=autoprune, api_tokens=msg_box_api_tokens,
                    head_message_sequence=head_message_sequence)

                msg_boxes.append(msg_box)
            return msg_boxes
        return read(self._database_context)

    def delete_msg_box(self, external_id: str) -> bool:
        def write(db: Optional[sqlite3.Connection]=None) -> bool:
            assert db is not None and isinstance(db, sqlite3.Connection)
            selectChannelByExternalId = "SELECT id FROM msg_box WHERE externalid = @msg_box_id;"
            result = db.execute(selectChannelByExternalId, (external_id,)).fetchone()
            if result is None:
                return False

            msg_box_id = result[0]
            # Peer Channels C# Reference evicts tokens from the cache and runs this query first:
            #   selectAPITokens = "SELECT * FROM msg_box_api_token WHERE msg_box_id = @msg_box_id;"
            #   apiTokens = cur.execute(selectChannelByExternalId).fetchall()
            # We are not using a cache (at the present moment) so this is skipped.

            statements = [
                """DELETE FROM message_status WHERE message_id IN (
                    SELECT id FROM message WHERE message.msg_box_id = @msg_box_id)""",
                "DELETE FROM message WHERE msg_box_id = @msg_box_id",
                "DELETE FROM msg_box_api_token WHERE msg_box_id = @msg_box_id",
                "DELETE FROM msg_box WHERE id = @msg_box_id",
            ]
            for sql in statements:
                db.execute(sql, (msg_box_id,))
            return True
        return self._database_context.run_in_thread(write)

    def create_api_token(self, api_token_view_model_create: view_models.APITokenViewModelCreate,
            msg_box_id: int, account_id: int) -> Optional[APITokenViewModelGet]:
        token = utils.create_channel_api_token()

        sql = """
            INSERT INTO msg_box_api_token
                (account_id, msg_box_id, token, description, canread, canwrite, validfrom)
            VALUES(@account_id, @msg_box_id, @token, @description, @canread, @canwrite, @validfrom)
            RETURNING id, token, description, canread, canwrite;
        """
        params = (account_id, msg_box_id, token,
            api_token_view_model_create.description,
            api_token_view_model_create.can_read,
            api_token_view_model_create.can_write,
            int(time.time())
        )
        def write(db: Optional[sqlite3.Connection]=None) \
                -> Optional[tuple[int, str, str, int, int]]:
            assert db is not None and isinstance(db, sqlite3.Connection)
            return cast(Optional[tuple[int, str, str, int, int]],
                db.execute(sql, params).fetchone())
        row = self._database_context.run_in_thread(write)
        if row is not None:
            id, token, description, canread, canwrite = row
            return APITokenViewModelGet(id=id, token=token, description=description,
                can_read=bool(canread), can_write=bool(canwrite))
        return None

    def get_api_token_by_id(self, token_id: int) -> Optional[APITokenViewModelGet]:
        sql = "SELECT id, token, description, canread, canwrite FROM msg_box_api_token " \
              "WHERE id = @token_id and (validto IS NULL OR validto >= @validto);"
        params = (token_id, int(time.time()))
        @replace_db_context_with_connection
        def read(db: sqlite3.Connection) -> Optional[APITokenViewModelGet]:
            rows = db.execute(sql, params).fetchall()
            if len(rows) != 0:
                id, token, description, canread, canwrite = rows[0]
                return APITokenViewModelGet(id=id, token=token, description=description,
                    can_read=bool(canread), can_write=bool(canwrite))
            return None
        return read(self._database_context)

    def get_api_token(self, token: str) -> Optional[MsgBoxAPIToken]:
        sql = """
            SELECT id, account_id, msg_box_id, token, description, canread, canwrite, validfrom,
                validto
            FROM msg_box_api_token
            WHERE token = @token and (validto IS NULL OR validto >= @validto)
        """
        params = (token, int(time.time()))
        @replace_db_context_with_connection
        def read(db: sqlite3.Connection) -> Optional[MsgBoxAPIToken]:
            row = db.execute(sql, params).fetchone()
            if row is not None:
                id, account_id, msg_box_id, token, description, canread, canwrite, validfrom, \
                    validto = row
                validfrom_dt = datetime.fromtimestamp(validfrom, tz=timezone.utc)
                validto_dt = datetime.fromtimestamp(validto, tz=timezone.utc) \
                    if validto is not None else None
                return MsgBoxAPIToken(id, account_id, msg_box_id, token, description, bool(canread),
                                      bool(canwrite), validfrom_dt, validto_dt)
            return None
        return read(self._database_context)

    def get_api_tokens(self, external_id: str, token: Optional[str]=None) \
            -> Optional[list[dict[str, Any]]]:
        sql = """
        SELECT msg_box_api_token.id, msg_box_api_token.token, msg_box_api_token.description,
            msg_box_api_token.canread, msg_box_api_token.canwrite
        FROM msg_box_api_token
        INNER JOIN msg_box ON msg_box_api_token.msg_box_id = msg_box.id
        WHERE msg_box.externalid = @external_id
          AND (msg_box_api_token.validto IS NULL OR msg_box_api_token.validto >= @validto)
          AND (@token IS NULL or msg_box_api_token.token = @token);
        """
        params = (external_id, int(time.time()), token)
        @replace_db_context_with_connection
        def read(db: sqlite3.Connection) -> Optional[list[dict[str, Any]]]:
            rows = db.execute(sql, params).fetchall()
            if len(rows) != 0:
                result = []
                for row in rows:
                    id, token, description, canread, canwrite = row
                    assert token is not None
                    view = APITokenViewModelGet(id=id, token=token, description=description,
                        can_read=bool(canread), can_write=bool(canwrite))
                    result.append(asdict(view))
                return result
            return None
        return read(self._database_context)

    def delete_api_token(self, token_id: int) -> None:
        sql = """UPDATE msg_box_api_token SET validto = @validto WHERE id = @tokenId;"""
        params = (int(time.time()), token_id)
        def write(db: Optional[sqlite3.Connection]=None) -> None:
            assert db is not None and isinstance(db, sqlite3.Connection)
            db.execute(sql, params)
        self._database_context.run_in_thread(write)

    def get_api_token_authorization_data_for_msg_box(self, externalid: str, token_id: int) \
            -> Optional[int]:
        """
        If the given message box api token with id `token_id` is linked to the message box
        with externalid `externalid` then we return the internal message box id `id`.
        """
        sql = """
            SELECT msg_box.id
            FROM msg_box_api_token
            INNER JOIN msg_box ON msg_box_api_token.msg_box_id = msg_box.id
            WHERE msg_box.externalid = @externalid and msg_box_api_token.id = @token_id
        """
        params = (externalid, token_id)
        @replace_db_context_with_connection
        def read(db: sqlite3.Connection) -> Optional[int]:
            rows = db.execute(sql, params).fetchall()
            assert len(rows) == 1
            return cast(int, rows[0][0])
        return read(self._database_context)

    def write_message(self, message: Message) -> tuple[int, MessageViewModelGet]:
        """Returns an error code and error reason"""
        def write(db: Optional[sqlite3.Connection]=None) \
                -> tuple[int, MessageViewModelGet]:
            assert db is not None and isinstance(db, sqlite3.Connection)
            # Translating this query from postgres -> SQLite
            # The "FOR UPDATE" lock can be dropped because SQLite does broad-brush/global db locking
            # For the entire transaction
            sql ="""
                SELECT locked, sequenced
                FROM msg_box
                WHERE id = @msg_box_id
                -- FOR UPDATE;
            """
            params = (message.msg_box_id, )
            rows = db.execute(sql, params).fetchall()
            if len(rows) != 0:
                locked, sequenced = rows[0]
                if locked:
                    raise PeerChannelMessageWriteError(code=APIErrors.CHANNEL_LOCKED)

                if sequenced:
                    unreadCount = self.get_unread_messages_count(db, message.msg_box_api_token_id)
                    if unreadCount > 0:
                        raise PeerChannelMessageWriteError(code=APIErrors.SEQUENCING_FAILURE)

            sql = """
                INSERT INTO message (fromtoken, msg_box_id, seq, receivedts, contenttype, payload)
                SELECT @fromtoken,
                       @msg_box_id,
                       COALESCE(MAX(seq) + 1, 1) AS seq,
                       @receivedts,
                       @contenttype,
                       @payload
                FROM message
                WHERE msg_box_id = @msg_box_id
                RETURNING * ;
            """
            params2 = (message.msg_box_api_token_id, message.msg_box_id, message.received_ts,
                message.content_type, message.payload)
            rows = db.execute(sql, params2).fetchall()
            message_id: int
            if len(rows) != 0:
                message_id, fromtoken, msg_box_id, seq, receivedts, contenttype, payload = rows[0]
                message_view_model_get = view_models.MessageViewModelGet(sequence=seq,
                    received=datetime.fromtimestamp(receivedts, tz=timezone.utc),
                    content_type=contenttype, payload=payload)
                self.logger.debug("Wrote message sequence: %s for msg_box_id: %s",
                    seq, msg_box_id)
            else:
                raise PeerChannelMessageWriteError(code=APIErrors.DATABASE_WRITE_FAILURE)

            sql = """
                INSERT INTO message_status
                    (message_id, token_id, isread, isdeleted)
                SELECT @messageid, msg_box_api_token.id,
                       CASE
                            WHEN msg_box_api_token.id = @fromtoken
                            THEN TRUE
                            ELSE FALSE
                        END AS isread,
                        FALSE AS isdeleted
                FROM msg_box_api_token
                WHERE validto IS NULL AND msg_box_id = @msg_box_id
            """
            params3 = (message_id, fromtoken, msg_box_id)
            db.execute(sql, params3)
            return message_id, message_view_model_get
        return self._database_context.run_in_thread(write)

    def get_unread_messages_count(self, db: sqlite3.Connection, msg_box_api_token_id: int) -> int:
        sql = """
            SELECT Count(*)
            FROM message_status
            WHERE message_status.token_id = @tokenid
              AND message_status.isread = FALSE
              AND message_status.isdeleted = FALSE
        """
        rows = db.execute(sql, (msg_box_api_token_id, )).fetchall()
        count = 0
        if len(rows) != 0:
            count = rows[0][0]
        return count

    def get_max_sequence(self, api_key: str, external_id: str) -> int:
        sql = """
            SELECT MAX(message.seq) AS max_sequence
            FROM message
            INNER JOIN msg_box ON msg_box.id = message.msg_box_id
            WHERE msg_box.externalid = @external_id
                AND msg_box.sequenced = true
                AND EXISTS(
                    SELECT 'x'
                    FROM msg_box_api_token
                    WHERE msg_box_api_token.token = @token
                        AND (msg_box_api_token.validto IS NULL
                        OR msg_box_api_token.validto >= @validto)
                        AND NOT msg_box_api_token.id = message.fromtoken
                )
                AND EXISTS(
                    SELECT 'x'
                    FROM message_status
                    WHERE message_status.message_id = message.id AND NOT message_status.isdeleted
                );
        """
        params = (external_id, api_key, int(time.time()))
        @replace_db_context_with_connection
        def read(db: sqlite3.Connection) -> int:
            rows = db.execute(sql, params).fetchall()
            seq = 0
            if len(rows) != 0:
                seq = rows[0][0]
            return seq if seq is not None else 0
        return read(self._database_context)

    def get_messages(self, api_token_id: int, onlyunread: bool) \
            -> tuple[list[Union[MessageViewModelGetJSON, MessageViewModelGetBinary]], str]:
        @replace_db_context_with_connection
        def read(db: sqlite3.Connection) \
                -> tuple[list[Union[MessageViewModelGetJSON, MessageViewModelGetBinary]], str]:
            sql = """
                SELECT msg_box.sequenced
                FROM msg_box
                INNER JOIN msg_box_api_token ON msg_box_api_token.msg_box_id = msg_box.id
                WHERE msg_box_api_token.id = @tokenid
                -- FOR UPDATE  # not needed for SQLite
            """
            rows = db.execute(sql, (api_token_id,)).fetchall()
            if len(rows) == 0:
                return [], ""

            sequenced = rows[0][0]
            if sequenced:
                sql = """
                    SELECT MAX(message.seq) AS max_sequence
                    FROM message
                    INNER JOIN message_status ON message_status.message_id = message.id
                    WHERE message_status.token_id = @tokenid AND NOT message_status.isdeleted;
                """
                sequence_row = db.execute(sql, (api_token_id,)).fetchone()
                max_sequence = str(sequence_row[0]) if sequence_row is not None else "0"
            else:
                max_sequence = ""

            sql = """
                SELECT message.*
                FROM message
                INNER JOIN message_status ON message_status.message_id = message.id
                INNER JOIN msg_box_api_token ON message_status.token_id = msg_box_api_token.id
                WHERE msg_box_api_token.id = @tokenid
                    AND message_status.isdeleted = false
                    AND (message_status.isread = false OR @onlyunread = false)
                ORDER BY message.seq;
            """

            sequence: int
            receivedts: int
            content_type: str
            payload: bytes
            messages = []
            for row in db.execute(sql, (api_token_id, onlyunread)).fetchall():
                id, fromtoken, msg_box_id, sequence, receivedts, content_type, payload = row

                message = view_models.MessageViewModelGet(
                    sequence=sequence,
                    received=datetime.fromtimestamp(receivedts, tz=timezone.utc),
                    content_type=content_type,
                    payload=payload,
                )
                messages.append(message.to_dict())
            return messages, max_sequence
        return read(self._database_context)

    def sequence_exists(self, token_id: int, sequence: int) -> bool:
        sql = """
            SELECT COUNT(message.seq) AS seq_count
            FROM message
            INNER JOIN message_status ON message_status.message_id = message.id
            WHERE message_status.token_id = @token_id
              AND message.seq = @seq;
        """
        params = (token_id, sequence)
        @replace_db_context_with_connection
        def read(db: sqlite3.Connection) -> bool:
            rows = db.execute(sql, params).fetchall()
            if len(rows) != 0:
                sequence_count: int = rows[0][0]
                return bool(sequence_count == 1)
            return False
        return read(self._database_context)

    def mark_messages(self, external_id: str, token_id: int, sequence: int, mark_older: bool,
            set_read_to: bool) -> None:
        sql = """
            UPDATE message_status SET isread = @isread
            WHERE message_status.message_id IN (
                SELECT message.id
                FROM message
                INNER JOIN msg_box ON message.msg_box_id = msg_box.id
                WHERE msg_box.externalid = @external_id
                AND (message.seq = @seq OR (message.seq < @seq AND @mark_older = true))
            )
            AND message_status.token_id = @token_id
        """
        def write(db: Optional[sqlite3.Connection]=None) -> None:
            assert db is not None and isinstance(db, sqlite3.Connection)
            params = (set_read_to, external_id, sequence, mark_older, token_id)
            db.execute(sql, params)
        self._database_context.run_in_thread(write)

    def get_message_metadata(self, external_id: str, sequence: int) -> Optional[MessageMetadata]:
        sql = """
            SELECT message.id, message.fromtoken, message.msg_box_id,
                message.seq, message.receivedts, message.contenttype
            FROM message
            INNER JOIN message_status ON message_status.message_id = message.id
            INNER JOIN msg_box ON message.msg_box_id = msg_box.id
            WHERE msg_box.externalid = @external_id
              AND message.seq = @seq
              AND message_status.isdeleted = false;
        """
        params = (external_id, sequence)
        @replace_db_context_with_connection
        def read(db: sqlite3.Connection) -> Optional[MessageMetadata]:
            rows = db.execute(sql, params).fetchall()
            if len(rows) != 0:
                id, fromtoken, msg_box_id, seq, receivedts, contenttype = rows[0]
                return MessageMetadata(
                    id=id,
                    msg_box_id=msg_box_id,
                    msg_box_api_token_id=fromtoken,
                    content_type=contenttype,
                    received_ts=datetime.fromtimestamp(receivedts, tz=timezone.utc)
                )
            return None
        return read(self._database_context)

    def delete_message(self, message_id: int, token_id: int) -> int:
        sql = "UPDATE message_status SET isdeleted = true " \
              "WHERE token_id = @token_id AND message_id = @message_id " \
              "RETURNING id;"
        def write(db: Optional[sqlite3.Connection]=None) -> int:
            assert db is not None and isinstance(db, sqlite3.Connection)
            rows = db.execute(sql, (token_id, message_id,)).fetchall()
            return len(rows)
        return self._database_context.run_in_thread(write)

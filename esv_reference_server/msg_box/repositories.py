"""
Copyright(c) 2021 Bitcoin Association.
Distributed under the Open BSV software license, see the accompanying file LICENSE
"""
import logging
from dataclasses import asdict

try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.10.0 builds and bundled version of 3.35.5.
    import sqlite3  # type: ignore

from typing import Optional, Union, List, Dict, Any
import typing
from datetime import datetime

from esv_reference_server import errors
from esv_reference_server.errors import Error
from esv_reference_server.msg_box import models, view_models, utils
from esv_reference_server.msg_box.models import MsgBox, MsgBoxAPIToken, MessageMetadata, Message
from esv_reference_server.msg_box.view_models import APITokenViewModelGet, MessageViewModelGetJSON, \
    MessageViewModelGetBinary, MsgBoxViewModelAmend

if typing.TYPE_CHECKING:
    from esv_reference_server.sqlite_db import SQLiteDatabase


# TODO - add indexes on relevant columns (beyond primary keys and foreign keys)


class MsgBoxSQLiteRepository:

    def __init__(self, sqlite: 'SQLiteDatabase'):
        self.logger = logging.getLogger("msg-box-sqlite-db")
        self.db = sqlite
        self.create_tables()

    def create_tables(self) -> None:
        self.create_message_box_table()
        self.create_messages_table()
        self.create_message_box_api_tokens_table()
        self.create_message_status_table()
        return None

    def create_message_box_table(self) -> None:
        """Modelled very closely on Peer Channels reference implementation:
        https://github.com/electrumsv/spvchannels-reference"""
        sql = ("""
            CREATE TABLE IF NOT EXISTS msg_box (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id    BIGINT             NOT NULL,
                externalid    VARCHAR(1024)      NOT NULL,
                publicread    boolean,
                publicwrite   boolean,
                locked        boolean,
                sequenced     boolean,
                minagedays    INT,
                maxagedays    INT,
                autoprune     boolean,

                UNIQUE (externalid),
                FOREIGN KEY(account_id) REFERENCES accounts(account_id)

            )""")
        self.db.execute2(sql)

    def create_messages_table(self) -> None:
        """Modelled very closely on Peer Channels reference implementation:
        https://github.com/electrumsv/spvchannels-reference"""
        sql = ("""
            CREATE TABLE IF NOT EXISTS message (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                fromtoken     BIGINT             NOT NULL,
                msg_box_id    BIGINT             NOT NULL,

                seq           BIGINT             NOT NULL,
                receivedts    TIMESTAMP          NOT NULL,
                contenttype   VARCHAR(64)        NOT NULL,
                payload       BYTEA,

                UNIQUE (msg_box_id, seq),
                FOREIGN KEY (fromtoken) REFERENCES msg_box_api_token (id),
                FOREIGN KEY (msg_box_id) REFERENCES msg_box (id)
            )""")
        self.db.execute2(sql)

    def create_message_status_table(self) -> None:
        """Modelled very closely on Peer Channels reference implementation:
        https://github.com/electrumsv/spvchannels-reference"""
        sql = (f"""
            CREATE TABLE IF NOT EXISTS message_status (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id    BIGINT             NOT NULL,
                token_id      BIGINT             NOT NULL,

                isread        boolean            NOT NULL,
                isdeleted     boolean            NOT NULL,
                
                FOREIGN KEY (message_id) REFERENCES message (id),
                FOREIGN KEY (token_id) REFERENCES msg_box_api_token (id)
            )""")
        self.db.execute2(sql)

    def create_message_box_api_tokens_table(self) -> None:
        """Modelled very closely on Peer Channels reference implementation:
        https://github.com/electrumsv/spvchannels-reference"""
        sql = ("""CREATE TABLE IF NOT EXISTS msg_box_api_token (
              id                    INTEGER PRIMARY KEY AUTOINCREMENT,
              account_id            BIGINT             NOT NULL,
              msg_box_id            BIGINT             NOT NULL,

              token		            VARCHAR(1024),
              description           VARCHAR(1024),
              canread               boolean,
              canwrite              boolean,
              validfrom             TIMESTAMP          NOT NULL,
              validto               TIMESTAMP,

              UNIQUE (token),
              FOREIGN KEY (account_id) REFERENCES accounts (account_id),
              FOREIGN KEY (msg_box_id) REFERENCES msg_box (id)
            )
            """)
        self.db.execute2(sql)
        return None

    def update_msg_box(self, msg_box_view_amend: MsgBoxViewModelAmend,
            external_id: str) -> Optional[view_models.MsgBoxViewModelAmend]:
        sql = f"""
            UPDATE msg_box
            SET  publicread= @publicread, publicwrite= @publicwrite, locked= @locked
            WHERE externalid= @externalid
            RETURNING *;
        """
        result = self.db.execute(sql, params=(msg_box_view_amend.public_read,
            msg_box_view_amend.public_write, msg_box_view_amend.locked, external_id))

        if not result:
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
        sql = f"""
            INSERT INTO msg_box (account_id, externalid, publicread, publicwrite, locked, 
                sequenced, minagedays, maxagedays, autoprune)
            VALUES(@owner, @externalid, @publicread, @publicwrite, @locked, 
                   @sequenced, @minagedays, @maxagedays, @autoprune)
            RETURNING *;
        """
        connection = self.db.acquire_connection()
        cur: sqlite3.Cursor = connection.cursor()
        cur.execute('BEGIN')
        try:
            cur.execute(sql, msg_box_row)

            id, account_id, externalid, publicread, \
                publicwrite, locked, sequenced, \
                minagedays, maxagedays, autoprune = cur.fetchone()

            msg_box_api_token_row = models.MsgBoxAPITokenRow(
                account_id=account_id,
                msg_box_id=id,
                token=utils.create_channel_api_token(),
                description="Owner",
                canread=True,
                canwrite=True,
                validfrom=datetime.utcnow(),
                validto=None
            )
            cur = self.create_msg_box_api_token(cur, msg_box_api_token_row)
            id, account_id, msg_box_id, token, description, \
                canread, canwrite, validfrom, validto = cur.fetchone()
            new_api_token = MsgBoxAPIToken(
                id=id,
                account_id=account_id,
                msg_box_id=msg_box_id,
                token=token,
                description=description,
                can_read=canread,
                can_write=canwrite,
                valid_from=validfrom,
                valid_to=validto
            )
            msg_box = MsgBox(id=id, account_id=account_id, external_id=externalid,
                public_read=publicread, public_write=publicwrite, locked=locked,
                sequenced=sequenced, min_age_days=minagedays, max_age_days=maxagedays,
                autoprune=autoprune, api_tokens=[new_api_token], head_message_sequence=0)
            cur.execute("COMMIT")
            return msg_box
        except Exception:
            cur.execute("ROLLBACK")
            self.logger.exception(f"An unexpected exception occurred for SQL: {sql}")
            raise
        finally:
            self.db.release_connection(connection)

    def create_msg_box_api_token(self, cur: sqlite3.Cursor,
            msg_box_api_token_row: models.MsgBoxAPITokenRow) -> sqlite3.Cursor:
        sql = f"""
            INSERT INTO msg_box_api_token (account_id, msg_box_id, token, description, canread, 
                canwrite, validfrom)
            VALUES(@account_id, @msg_box_id, @token, @description, @canread, @canwrite, @validfrom)
            RETURNING *;
        """
        account_id, msg_box_externalid, token, description, canread, canwrite, validfrom, \
            validto = msg_box_api_token_row
        return cur.execute(sql, (account_id, msg_box_externalid, token, description, canread,
                                 canwrite, validfrom))

    def get_msg_box_tokens(self, msg_box_id: int) -> list[MsgBoxAPIToken]:
        sql = f"""SELECT * FROM msg_box_api_token WHERE msg_box_id = ?;"""
        rows = self.db.execute(sql, params=(msg_box_id,))
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

    def get_msg_box(self, account_id: int, externalid: str) -> Optional[MsgBox]:
        sql = f"""
            SELECT id, account_id, externalid, publicread, publicwrite, locked, sequenced, 
                   minagedays, maxagedays, autoprune, 
                   (SELECT max(seq) FROM message WHERE msg_box.id = message.msg_box_id) AS seq
            FROM msg_box
            WHERE account_id = @account_id AND externalid = @externalid;
        """
        rows = self.db.execute(sql, params=(account_id, externalid))
        if len(rows) == 0:
            return None

        id, account_id, externalid, publicread, publicwrite, locked, \
            sequenced, minagedays, maxagedays, autoprune, head_message_sequence = rows[0]
        msg_box_api_tokens = self.get_msg_box_tokens(id)
        head_message_sequence = head_message_sequence if head_message_sequence else 0

        msg_box = MsgBox(id=id, account_id=account_id, external_id=externalid,
            public_read=publicread, public_write=publicwrite, locked=locked,
            sequenced=sequenced, min_age_days=minagedays, max_age_days=maxagedays,
            autoprune=autoprune, api_tokens=msg_box_api_tokens,
            head_message_sequence=head_message_sequence)

        return msg_box

    def get_msg_boxes(self, account_id: int) -> list[MsgBox]:
        sql = f"""
            SELECT id, account_id, externalid, publicread, publicwrite, locked, sequenced, 
                   minagedays, maxagedays, autoprune, 
                   (SELECT max(seq) FROM message WHERE msg_box.id = message.msg_box_id) AS seq
            FROM msg_box
            WHERE account_id = @account_id;
        """
        rows = self.db.execute(sql, params=(account_id,))

        msg_boxes = []
        for row in rows:
            id, account_id, externalid, publicread, publicwrite, \
                locked, sequenced, minagedays, maxagedays, autoprune, head_message_sequence = row
            msg_box_api_tokens = self.get_msg_box_tokens(id)
            head_message_sequence = head_message_sequence if head_message_sequence else 0

            msg_box = MsgBox(id=id, account_id=account_id, external_id=externalid,
                public_read=publicread, public_write=publicwrite, locked=locked,
                sequenced=sequenced, min_age_days=minagedays, max_age_days=maxagedays,
                autoprune=autoprune, api_tokens=msg_box_api_tokens,
                head_message_sequence=head_message_sequence)

            msg_boxes.append(msg_box)
        return msg_boxes

    def delete_msg_box(self, msg_box_id: str) -> bool:
        connection = self.db.acquire_connection()
        cur: sqlite3.Cursor = connection.cursor()
        cur.execute('BEGIN')
        sql = None
        try:
            selectChannelByExternalId = "SELECT id FROM msg_box WHERE externalid = @msg_box_id;"
            result = cur.execute(selectChannelByExternalId, (msg_box_id,)).fetchone()
            if not result:
                return False

            msg_box_id = result[0]
            # Peer Channels C# Reference evicts tokens from the cache and runs this query first:
            #   selectAPITokens = "SELECT * FROM msg_box_api_token WHERE msg_box_id = @msg_box_id;"
            #   apiTokens = cur.execute(selectChannelByExternalId).fetchall()
            # We are not using a cache (at the present moment) so this is skipped.

            statements = [
                """DELETE FROM message_status
                        WHERE message_id IN (
                            SELECT id FROM message WHERE message.msg_box_id = @msg_box_id
                        );""",
                """DELETE FROM message WHERE msg_box_id = @msg_box_id;""",
                """DELETE FROM msg_box_api_token WHERE msg_box_id = @msg_box_id;""",
                """DELETE FROM msg_box WHERE id = @msg_box_id;""",
            ]
            for sql in statements:
                cur.execute(sql, (msg_box_id,))
            cur.execute("COMMIT")
            return True
        except Exception:
            cur.execute("ROLLBACK")
            if sql:
                self.logger.exception(f"An unexpected exception occurred for SQL: {sql}")
            else:
                self.logger.exception(f"An unexpected exception occurred")
            raise
        finally:
            self.db.release_connection(connection)

    def create_api_token(self, api_token_view_model_create: view_models.APITokenViewModelCreate,
            msg_box_id: int, account_id: int) -> Optional[APITokenViewModelGet]:
        token = utils.create_channel_api_token()

        sql = """
            INSERT INTO msg_box_api_token 
                (account_id, msg_box_id, token, description, canread, canwrite, validfrom)
            VALUES(@account_id, @msg_box_id, @token, @description, @canread, @canwrite, @validfrom)
            RETURNING *;
        """
        params = (account_id, msg_box_id, token,
            api_token_view_model_create.description,
            api_token_view_model_create.can_read,
            api_token_view_model_create.can_write,
            datetime.utcnow()
        )
        rows = self.db.execute(sql, params)
        if len(rows) != 0:
            id, account_id, msg_box_id, token, \
                description, canread, canwrite, validfrom, validto = rows[0]
            return APITokenViewModelGet(id=id, token=token, description=description,
                can_read=canread, can_write=canwrite)
        return None

    def get_api_token_by_id(self, token_id: int) -> Optional[APITokenViewModelGet]:
        sql = "SELECT * FROM msg_box_api_token " \
              "WHERE id = @token_id and (validto IS NULL OR validto >= @validto);"
        params = (token_id, datetime.utcnow())
        rows = self.db.execute(sql, params)
        if len(rows) != 0:
            id, account_id, msg_box_id, token, \
                description, canread, canwrite, validfrom, validto = rows[0]
            return APITokenViewModelGet(id=id, token=token, description=description,
                can_read=canread, can_write=canwrite)
        return None

    # Todo - Add an LRU cache for this request
    def get_api_token(self, token: str) -> Optional[MsgBoxAPIToken]:
        sql = "SELECT * FROM msg_box_api_token " \
              "WHERE token = @token and (validto IS NULL OR validto >= @validto);"
        params = (token, datetime.utcnow())
        rows = self.db.execute(sql, params)
        if len(rows) != 0:
            id, account_id, msg_box_id, token, description, \
                canread, canwrite, validfrom, validto = rows[0]
            return MsgBoxAPIToken(id, account_id, msg_box_id,
                token, description, canread, canwrite, validfrom, validto)
        return None

    def get_api_tokens(self, external_id: str, token: Optional[str]=None) \
            -> Optional[List[Dict[str, Any]]]:
        sql = """
        SELECT msg_box_api_token.*
        FROM msg_box_api_token
        INNER JOIN msg_box ON msg_box_api_token.msg_box_id = msg_box.id
        WHERE msg_box.externalid = @external_id
          AND (msg_box_api_token.validto IS NULL OR msg_box_api_token.validto >= @validto) 
          AND (@token IS NULL or msg_box_api_token.token = @token);
        """
        params = (external_id, datetime.utcnow(), token)
        rows = self.db.execute(sql, params)
        if len(rows) != 0:
            result = []
            for row in rows:
                id, account_id, msg_box_id, token, description, canread, canwrite, \
                    validfrom, validto = row
                assert token is not None
                view: APITokenViewModelGet = APITokenViewModelGet(id=id, token=token, description=description,
                    can_read=canread, can_write=canwrite)
                result.append(asdict(view))
            return result
        return None

    def delete_api_token(self, token_id: int) -> None:
        sql = """UPDATE msg_box_api_token SET validto = @validto WHERE id = @tokenId;"""
        params = (datetime.utcnow(), token_id)
        self.db.execute(sql, params)

    def is_authorized_to_msg_box_api_token(self, externalid: str, token_id: int) -> bool:
        sql = """
            SELECT COUNT('x') FROM msg_box_api_token
            INNER JOIN msg_box ON msg_box_api_token.msg_box_id = msg_box.id
            WHERE msg_box.externalid = @externalid and msg_box_api_token.id = @token_id
        """
        params = (externalid, token_id)
        rows = self.db.execute(sql, params)
        if len(rows) != 0:
            result = rows[0][0]
            if result != 0:
                return True
        return False

    def write_message(self, message: Message) -> Union[tuple[int, view_models.MessageViewModelGet], Error]:
        """Returns an error code and error reason"""
        connection = self.db.acquire_connection()
        cur: sqlite3.Cursor = connection.cursor()
        cur.execute('BEGIN')
        sql = None
        try:
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
            rows = cur.execute(sql, params).fetchall()
            if len(rows) != 0:
                locked, sequenced = rows[0]
                if locked:
                    error_code = errors.ChannelLocked.status
                    error_reason = errors.ChannelLocked.reason
                    raise Error(reason=error_reason, status=error_code)

                if sequenced:
                    unreadCount = self.get_unread_messages_count(cur, message.msg_box_api_token_id)
                    if unreadCount > 0:
                        error_code = errors.SequencingFailure.status
                        error_reason = errors.SequencingFailure.reason
                        raise Error(reason=error_reason, status=error_code)

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
            rows = cur.execute(sql, params2).fetchall()
            if len(rows) != 0:
                message_id, fromtoken, msg_box_id, seq, receivedts, contenttype, payload = rows[0]
                message_view_model_get = view_models.MessageViewModelGet(sequence=seq,
                    received=datetime.fromisoformat(receivedts),
                    content_type=contenttype, payload=payload)
                self.logger.debug(f"Wrote message sequence: {seq} for msg_box_id: {msg_box_id}")
            else:
                raise Error(reason="Failed to insert message", status=500)

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
            cur.execute(sql, params3)
            cur.execute("COMMIT")
            return message_id, message_view_model_get
        except Exception as error:
            cur.execute("ROLLBACK")
            if sql:
                self.logger.exception(f"An unexpected exception occurred for SQL: {sql}")
            else:
                self.logger.exception(f"An unexpected exception occurred")
            raise error
        finally:
            self.db.release_connection(connection)

    def get_unread_messages_count(self, cursor: sqlite3.Cursor, msg_box_api_token_id: int) -> int:
        sql = """
            SELECT Count(*)
            FROM message_status
            WHERE message_status.token_id = @tokenid
              AND message_status.isread = FALSE
              AND message_status.isdeleted = FALSE
        """
        params = (msg_box_api_token_id, )
        rows = cursor.execute(sql, params).fetchall()
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
        params = (external_id, api_key, datetime.utcnow())
        rows = self.db.execute(sql, params)
        seq = 0
        if len(rows) != 0:
            seq = rows[0][0]
        return seq

    def get_messages(self, api_token_id: int, onlyunread: bool) \
            -> Optional[tuple[list[Union[MessageViewModelGetJSON, MessageViewModelGetBinary]], Union[int, str]]]:
        connection = self.db.acquire_connection()
        cur: sqlite3.Cursor = connection.cursor()
        cur.execute('BEGIN')
        sql = None
        try:

            sql = """
                SELECT msg_box.sequenced
                FROM msg_box
                INNER JOIN msg_box_api_token ON msg_box_api_token.msg_box_id = msg_box.id 
                WHERE msg_box_api_token.id = @tokenid 
                -- FOR UPDATE  # not needed for SQLite
            """
            params = (api_token_id, )
            rows = cur.execute(sql, params).fetchall()
            if len(rows) != 0:
                sequenced = rows[0][0]
            else:
                return None

            if sequenced:
                sql = """
                    SELECT MAX(message.seq) AS max_sequence
                    FROM message
                    INNER JOIN message_status ON message_status.message_id = message.id
                    WHERE message_status.token_id = @tokenid AND NOT message_status.isdeleted;
                """
                params2 = (api_token_id,)
                rows = cur.execute(sql, params2).fetchall()
                if len(rows) != 0:
                    max_seq = rows[0][0]
                    if max_seq is None:
                        max_seq = 0
                else:
                    max_seq = ""
            else:
                return None

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
            params3 = (api_token_id, onlyunread)
            rows = cur.execute(sql, params3).fetchall()
            cur.execute("COMMIT")

            messages = []
            if len(rows) != 0:
                sequence: int
                received: datetime
                content_type: str
                payload: bytes
                for row in rows:
                    id, fromtoken, msg_box_id, seq, receivedts, contenttype, payload = row

                    message = view_models.MessageViewModelGet(
                        sequence=seq,
                        received=datetime.fromisoformat(receivedts),
                        content_type=contenttype,
                        payload=payload,
                    )
                    messages.append(message.to_dict())
            return messages, max_seq
        except Exception:
            cur.execute("ROLLBACK")
            if sql:
                self.logger.exception(f"An unexpected exception occurred for SQL: {sql}")
            else:
                self.logger.exception(f"An unexpected exception occurred")
            raise
        finally:
            self.db.release_connection(connection)

    def sequence_exists(self, token_id: int, sequence: int) -> bool:
        sql = """
            SELECT COUNT(message.seq) AS seq_count
            FROM message
            INNER JOIN message_status ON message_status.message_id = message.id
            WHERE message_status.token_id = @token_id
              AND message.seq = @seq;
        """
        params = (token_id, sequence)
        rows = self.db.execute(sql, params)
        if len(rows) != 0:
            sequence_count: int = rows[0][0]
            return bool(sequence_count == 1)
        return False

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
        params = (set_read_to, external_id, sequence, mark_older, token_id)
        self.db.execute2(sql, params)

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
        rows = self.db.execute(sql, params)
        if len(rows) != 0:
            id, fromtoken, msg_box_id, seq, receivedts, contenttype = rows[0]
            return MessageMetadata(
                id=id,
                msg_box_id=msg_box_id,
                msg_box_api_token_id=fromtoken,
                content_type=contenttype,
                received_ts=datetime.fromisoformat(receivedts)
            )
        return None

    def delete_message(self, message_id: int) -> int:
        sql = "UPDATE message_status SET isdeleted = true " \
              "WHERE message_id = @message_id RETURNING id;"
        params = (message_id,)
        rows = self.db.execute(sql, params)
        count_deleted = len(rows)
        return count_deleted

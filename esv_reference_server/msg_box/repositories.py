import logging
import sqlite3
import typing
from typing import Optional
from datetime import datetime

from esv_reference_server.msg_box import models, view_models, utils
from esv_reference_server.msg_box.models import MsgBox, MsgBoxAPIToken
from esv_reference_server.msg_box.view_models import APITokenViewModelGet

if typing.TYPE_CHECKING:
    from esv_reference_server.sqlite_db import SQLiteDatabase


# TODO - add indexes on relevant columns (beyond primary keys and foreign keys)


class MsgBoxSQLiteRepository:

    def __init__(self, sqlite: 'SQLiteDatabase'):
        self.logger = logging.getLogger("msg-box-sqlite-repository")
        self.db = sqlite
        self.create_tables()

    def create_tables(self):
        self.create_message_box_table()
        self.create_messages_table()
        self.create_message_box_api_tokens_table()
        self.create_message_status_table()

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
                id            BIGSERIAL          NOT NULL,
                message_id    BIGINT             NOT NULL,
                token_id      BIGINT             NOT NULL,

                isread        boolean            NOT NULL,
                isdeleted     boolean            NOT NULL,
                
                PRIMARY KEY (id),
                FOREIGN KEY (message_id) REFERENCES message (id),
                FOREIGN KEY (token_id) REFERENCES msg_box_api_token (id)
            )""")
        self.db.execute2(sql)

    def create_message_box_api_tokens_table(self):
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

    def update_msg_box(self, msg_box_view_amend: view_models.MsgBoxViewModelAmend,
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
            return

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
            INSERT INTO msg_box (account_id, externalid, publicread, publicwrite, locked, sequenced, minagedays, maxagedays, autoprune)
            VALUES(@owner, @externalid, @publicread, @publicwrite, @locked, @sequenced, @minagedays, @maxagedays, @autoprune)
            RETURNING *;
        """
        connection = self.db.acquire_connection()
        cur: sqlite3.Cursor = connection.cursor()
        cur.execute('BEGIN')
        try:
            cur.execute(sql, msg_box_row)

            id, account_id, externalid, publicread, publicwrite, locked, sequenced, \
                minagedays, maxagedays, autoprune = cur.fetchone()

            msg_box_api_token_row = models.MsgBoxAPITokenRow(
                account_id=account_id,
                msg_box_id=id,
                token=utils.create_channel_api_token(),
                description="Owner",
                canread=True,
                canwrite=True,
                validfrom=datetime.utcnow(),
            )
            cur = self.create_msg_box_api_token(cur, msg_box_api_token_row)
            id, account_id, msg_box_id, token, description, canread, canwrite, validfrom, validto = cur.fetchone()
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
            INSERT INTO msg_box_api_token (account_id, msg_box_id, token, description, canread, canwrite, validfrom)
            VALUES(@account_id, @msg_box_id, @token, @description, @canread, @canwrite, @validfrom)
            RETURNING *;
        """
        return cur.execute(sql, msg_box_api_token_row)

    def get_msg_box_tokens(self, msg_box_id: int) -> list[MsgBoxAPIToken]:
        sql = f"""SELECT * FROM msg_box_api_token WHERE msg_box_id = ?;"""
        rows = self.db.execute(sql, params=(msg_box_id,))
        msg_box_api_tokens = []
        for row in rows:
            row: models.MsgBoxAPITokenRow
            id, account_id, msg_box_externalid, token, description, canread, canwrite, validfrom, validto = row
            msg_api_token = MsgBoxAPIToken(id=id, account_id=account_id, msg_box_id=msg_box_id,
                token=token, description=description, can_read=canread, can_write=canwrite,
                valid_from=validfrom, valid_to=validto)
            msg_box_api_tokens.append(msg_api_token)
        return msg_box_api_tokens

    def get_msg_box(self, account_id: int, externalid: str) -> Optional[MsgBox]:
        sql = f"""
            SELECT id, account_id, externalid, publicread, publicwrite, locked, sequenced, minagedays, 
                maxagedays, autoprune, (select max(seq) FROM message where msg_box.id = message.msg_box_id) AS seq
            FROM msg_box
            WHERE account_id = @account_id AND externalid = @externalid;
        """
        rows = self.db.execute(sql, params=(account_id, externalid))
        if len(rows) == 0:
            return

        id, account_id, externalid, publicread, publicwrite, locked, sequenced, minagedays, maxagedays, autoprune, head_message_sequence = rows[0]
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
            SELECT id, account_id, externalid, publicread, publicwrite, locked, sequenced, minagedays, 
                maxagedays, autoprune, (select max(seq) FROM message where msg_box.id = message.msg_box_id) AS seq
            FROM msg_box
            WHERE account_id = @account_id;
        """
        rows = self.db.execute(sql, params=(account_id,))

        msg_boxes = []
        for row in rows:
            id, account_id, externalid, publicread, publicwrite, locked, sequenced, minagedays, maxagedays, autoprune, head_message_sequence = row
            msg_box_api_tokens = self.get_msg_box_tokens(id)
            head_message_sequence = head_message_sequence if head_message_sequence else 0

            msg_box = MsgBox(id=id, account_id=account_id, external_id=externalid,
                public_read=publicread, public_write=publicwrite, locked=locked,
                sequenced=sequenced, min_age_days=minagedays, max_age_days=maxagedays,
                autoprune=autoprune, api_tokens=msg_box_api_tokens,
                head_message_sequence=head_message_sequence)

            msg_boxes.append(msg_box)
        return msg_boxes

    def delete_msg_box(self, msg_box_id: str) -> Optional[bool]:
        connection = self.db.acquire_connection()
        cur: sqlite3.Cursor = connection.cursor()
        cur.execute('BEGIN')
        sql = None
        try:
            selectChannelByExternalId = "SELECT id FROM msg_box WHERE externalid = @msg_box_id;"
            result = cur.execute(selectChannelByExternalId, (msg_box_id,)).fetchone()
            if not result:
                return

            msg_box_id = result[0]
            # Peer Channels Reference uses this query to subsequently evict tokens from the cache
            # we are using the SQLite cache so do not need to do this
            # selectAPITokens = "SELECT * FROM msg_box_api_token WHERE msg_box_id = @msg_box_id;"
            # apiTokens = cur.execute(selectChannelByExternalId).fetchall()
            statements = [
                """DELETE FROM message_status 
                        WHERE message_id IN (SELECT id FROM message WHERE message.msg_box_id = @msg_box_id);""",
                """DELETE FROM message WHERE msg_box_id = @msg_box_id;""",
                """DELETE FROM msg_box_api_token WHERE msg_box_id = @msg_box_id;""",
                """DELETE FROM msg_box WHERE id = @msg_box_id;""",
            ]
            for sql in statements:
                cur.execute(sql, (msg_box_id,))
            cur.execute("COMMIT")
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
            msg_box_id: int, account_id: int) -> APITokenViewModelGet:
        token = utils.create_channel_api_token()

        sql = """
            INSERT INTO msg_box_api_token (account_id, msg_box_id, token, description, canread, canwrite, validfrom)
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
            id, account_id, msg_box_id, token, description, canread, canwrite, validfrom, validto = rows[0]
            return APITokenViewModelGet(id=id, token=token, description=description, can_read=canread, can_write=canwrite)

    def get_api_token(self, token_id: int) -> APITokenViewModelGet:
        sql = "SELECT * FROM msg_box_api_token " \
              "WHERE id = @token_id and (validto IS NULL OR validto >= @validto);"
        params = (token_id, datetime.utcnow())
        rows = self.db.execute(sql, params)
        if len(rows) != 0:
            id, account_id, msg_box_id, token, description, canread, canwrite, validfrom, validto = rows[0]
            return APITokenViewModelGet(id=id, token=token, description=description,
                can_read=canread, can_write=canwrite)

    def get_api_tokens(self, external_id: str, token: Optional[str]) \
            -> Optional[list[APITokenViewModelGet]]:
        sql = """
        SELECT msg_box_api_token.*
        FROM msg_box_api_token
        INNER JOIN msg_box ON msg_box_api_token.msg_box_id = msg_box.id
        WHERE msg_box.externalid = @external_id
          AND (msg_box_api_token.validto IS NULL OR msg_box_api_token.validto >= @validto) and (@token IS NULL or msg_box_api_token.token = @token);
        """
        params = (external_id, datetime.utcnow(), token)
        rows = self.db.execute(sql, params)
        if len(rows) != 0:
            result = []
            for row in rows:
                id, account_id, msg_box_id, token, description, canread, canwrite, validfrom, validto = row
                view = APITokenViewModelGet(id=id, token=token, description=description, can_read=canread, can_write=canwrite)
                result.append(view.to_dict())
            return result

    def delete_api_token(self, token_id):
        sql = """UPDATE msg_box_api_token SET validto = @validto WHERE id = @tokenId;"""
        params = (datetime.utcnow(), token_id)
        result = self.db.execute(sql, params)
        return result

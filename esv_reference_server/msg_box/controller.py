"""
Copyright(c) 2021 Bitcoin Association.
Distributed under the Open BSV software license, see the accompanying file LICENSE
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timedelta
from json import JSONDecodeError
from typing import TYPE_CHECKING, Optional

import aiohttp
from aiohttp import web

from esv_reference_server import errors
from esv_reference_server.errors import Error
from esv_reference_server.msg_box.models import MsgBox, Message, PushNotification
from esv_reference_server.msg_box.repositories import MsgBoxSQLiteRepository
from esv_reference_server.msg_box.view_models import RetentionViewModel, MsgBoxViewModelGet, \
    MsgBoxViewModelCreate, MsgBoxViewModelAmend, APITokenViewModelCreate
from esv_reference_server.types import MsgBoxWSClient

if TYPE_CHECKING:
    from esv_reference_server.server import ApplicationState
    from esv_reference_server.sqlite_db import SQLiteDatabase


logger = logging.getLogger('handlers-peer-channels')


def _try_read_bearer_token(request: web.Request) -> Optional[str]:
    auth_string = request.headers.get('Authorization', None)
    if auth_string is None or not auth_string.startswith("Bearer "):
        return
    api_key = auth_string[7:]
    return api_key


def _auth_ok(api_key: str, db: SQLiteDatabase) -> bool:
    account_id, _account_flags = db.get_account_id_for_api_key(api_key)
    if account_id is None:
        # return False
        # TODO - put this back to False after implementation is complete
        return True
    return True


def _auth_for_channel_token(token: str, external_id: str, msg_box_repository: MsgBoxSQLiteRepository) -> bool:
    token_object = msg_box_repository.get_api_token(token)
    if not token_object:
        return False
    return msg_box_repository.is_authorized_to_msg_box_api_token(external_id, token_object.id)


def _msg_box_get_view(request: web.Request, msg_box: MsgBox):
    get_messages_route = request.app.router.get('get_messages').canonical.format(
        channelid=msg_box.external_id)
    base_url = str(request.url).replace(request.url.path, "")
    get_messages_href = base_url + get_messages_route
    msg_box_view_get = MsgBoxViewModelGet.from_msg_box(msg_box, href=get_messages_href)
    return msg_box_view_get


# ----- CHANNEL MANAGEMENT APIs ----- #
async def list_channels(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
    db: SQLiteDatabase = app_state.sqlite_db

    api_key = _try_read_bearer_token(request)
    if not api_key:
        return web.Response(reason=errors.NoBearerToken.reason, status=errors.NoBearerToken.status)

    if not _auth_ok(api_key, db):
        raise web.HTTPUnauthorized

    # Todo - get the account_id from db and return HTTPNotFound if not found
    # Todo - check the account_id against the channel_id to ensure this user
    #  has the required read/write permissions
    account_id = 0
    logger.info(f"Get list of message boxes for accountid: {account_id}.")

    msg_boxes: list[MsgBox] = msg_box_repository.get_msg_boxes(account_id)
    result = []
    for msg_box in msg_boxes:
        msg_box_view_get = _msg_box_get_view(request, msg_box)
        result.append(msg_box_view_get.to_dict())
    logger.info(f"Returning {len(msg_boxes)} channels for account_id: {account_id}.")
    return web.json_response(result)


async def get_single_channel_details(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
    db: SQLiteDatabase = app_state.sqlite_db

    api_key = _try_read_bearer_token(request)
    if not api_key:
        return web.Response(reason=errors.NoBearerToken.reason, status=errors.NoBearerToken.status)

    if not _auth_ok(api_key, db):
        raise web.HTTPUnauthorized

    # Todo - get the account_id from db and return HTTPNotFound if not found
    # Todo - check the account_id against the channel_id to ensure this user
    #  has the required read/write permissions
    account_id = 0
    external_id = request.match_info.get('channelid')

    logger.info(f"Get message box by external_id {external_id} for account(id) {account_id}.")
    msg_box: MsgBox = msg_box_repository.get_msg_box(account_id, external_id)
    if not msg_box:
        raise web.HTTPNotFound
    msg_box_view_get = _msg_box_get_view(request, msg_box)
    logger.info(f"Returning message box by external_id: {external_id}.")
    return web.json_response(msg_box_view_get.to_dict())


async def update_single_channel_properties(request: web.Request) -> web.Response:
    try:
        app_state: ApplicationState = request.app['app_state']
        msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
        db: SQLiteDatabase = app_state.sqlite_db

        api_key = _try_read_bearer_token(request)
        if not api_key:
            return web.Response(reason=errors.NoBearerToken.reason, status=errors.NoBearerToken.status)

        if not _auth_ok(api_key, db):
            raise web.HTTPUnauthorized

        # Todo - get the account_id from db and return HTTPNotFound if not found
        # Todo - check the account_id against the channel_id to ensure this user
        #  has the required read/write permissions
        account_id = 0
        external_id = request.match_info.get('channelid')
        body = await request.json()
        msg_box_view_amend = MsgBoxViewModelAmend(**body)

        logger.info(f"Updating message box by external_id {external_id} for account(id) {account_id}.")
        msg_box_view_amend: MsgBoxViewModelAmend = msg_box_repository.update_msg_box(
            msg_box_view_amend, external_id)
        if not msg_box_view_amend:
            raise web.HTTPNotFound
        logger.info(f"Message box with external_id: {external_id} was updated.")
        return web.json_response(msg_box_view_amend.to_dict())
    except JSONDecodeError as e:
        logger.exception(e)
        return web.Response(reason="JSONDecodeError: " + str(e), status=400)


async def delete_channel(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
    db: SQLiteDatabase = app_state.sqlite_db

    api_key = _try_read_bearer_token(request)
    if not api_key:
        return web.Response(reason=errors.NoBearerToken.reason, status=errors.NoBearerToken.status)

    if not _auth_ok(api_key, db):
        raise web.HTTPUnauthorized

    # Todo - get the account_id from db and return HTTPNotFound if not found
    # Todo - check the account_id against the channel_id to ensure this user
    #  has the required read/write permissions
    account_id = 0
    external_id = request.match_info.get('channelid')

    logger.info(f"Deleting message box by external_id {external_id} for account(id) {account_id}.")
    msg_box_view_delete: MsgBoxViewModelAmend = msg_box_repository.delete_msg_box(external_id)

    logger.info(f"Channel Deleted.")
    return web.HTTPNoContent()


async def create_new_channel(request: web.Request) -> web.Response:
    try:
        app_state: ApplicationState = request.app['app_state']
        msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
        db: SQLiteDatabase = app_state.sqlite_db

        api_key = _try_read_bearer_token(request)
        if not api_key:
            return web.Response(reason=errors.NoBearerToken.reason, status=errors.NoBearerToken.status)

        if not _auth_ok(api_key, db):
            raise web.HTTPUnauthorized

        # Todo - get the account_id from db and return HTTPNotFound if not found
        # Todo - check the account_id against the channel_id to ensure this user
        #  has the required read/write permissions
        account_id = 0

        logger.info(f"Creating new message box for account_id: {account_id}.")
        body = await request.json()
        retention_view_model = RetentionViewModel(**body['retention'])
        if not retention_view_model.is_valid():
            return web.Response(reason=errors.RetentionInvalidMinMax, status=errors.RetentionInvalidMinMax.status)

        msg_box_view_create = MsgBoxViewModelCreate.from_request(body)
        msg_box: MsgBox = msg_box_repository.create_message_box(msg_box_view_create,
            account_id)

        msg_box_view_get = _msg_box_get_view(request, msg_box)
        logger.info(f"New message box for account_id {account_id} was created external_id: {msg_box_view_get.external_id}.");
        return web.json_response(msg_box_view_get.to_dict())
    except JSONDecodeError as e:
        logger.exception(e)
        return web.Response(reason="JSONDecodeError: " + str(e), status=400)


async def revoke_selected_token(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
    db: SQLiteDatabase = app_state.sqlite_db

    api_key = _try_read_bearer_token(request)
    if not api_key:
        return web.Response(reason=errors.NoBearerToken.reason, status=errors.NoBearerToken.status)

    if not _auth_ok(api_key, db):
        raise web.HTTPUnauthorized

    # Todo - get the account_id from db and return HTTPNotFound if not found
    # Todo - check the account_id against the channel_id to ensure this user
    #  has the required read/write permissions
    account_id = 0
    _external_id = request.match_info.get('channelid')
    token_id = request.match_info.get('tokenid')

    msg_box_repository.delete_api_token(token_id)
    return web.HTTPNoContent()


async def get_token_details(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
    db: SQLiteDatabase = app_state.sqlite_db

    api_key = _try_read_bearer_token(request)
    if not api_key:
        return web.Response(reason=errors.NoBearerToken.reason, status=errors.NoBearerToken.status)

    if not _auth_ok(api_key, db):
        raise web.HTTPUnauthorized

    # Todo - get the account_id from db and return HTTPNotFound if not found
    # Todo - check the account_id against the channel_id to ensure this user
    #  has the required read/write permissions
    account_id = 0
    _external_id = request.match_info.get('channelid')
    token_id = request.match_info.get('tokenid')

    api_token_view_model_get = msg_box_repository.get_api_token_by_id(token_id)
    if not api_token_view_model_get:
        raise web.HTTPNotFound
    return web.json_response(api_token_view_model_get.to_dict())


async def get_list_of_tokens(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
    db: SQLiteDatabase = app_state.sqlite_db

    api_key = _try_read_bearer_token(request)
    if not api_key:
        return web.Response(reason=errors.NoBearerToken.reason, status=errors.NoBearerToken.status)

    if not _auth_ok(api_key, db):
        raise web.HTTPUnauthorized

    # Todo - get the account_id from db and return HTTPNotFound if not found
    # Todo - check the account_id against the channel_id to ensure this user
    #  has the required read/write permissions
    account_id = 0
    external_id = request.match_info.get('channelid')
    token = request.query.get('token')

    list_api_token_view_model_get = msg_box_repository.get_api_tokens(external_id, token)
    if not list_api_token_view_model_get:
        raise web.HTTPNotFound
    return web.json_response(list_api_token_view_model_get)


async def create_new_token_for_channel(request: web.Request) -> web.Response:
    try:
        app_state: ApplicationState = request.app['app_state']
        msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
        db: SQLiteDatabase = app_state.sqlite_db

        api_key = _try_read_bearer_token(request)
        if not api_key:
            return web.Response(reason=errors.NoBearerToken.reason, status=errors.NoBearerToken.status)

        if not _auth_ok(api_key, db):
            raise web.HTTPUnauthorized

        # Todo - get the account_id from db and return HTTPNotFound if not found
        # Todo - check the account_id against the channel_id to ensure this user
        #  has the required read/write permissions
        account_id = 0
        external_id = request.match_info.get('channelid')

        msg_box = msg_box_repository.get_msg_box(account_id, external_id)
        if not msg_box:
            raise web.HTTPNotFound

        body = await request.json()
        api_token_view_model_create = APITokenViewModelCreate(**body)
        api_token_view_model_get = msg_box_repository.create_api_token(api_token_view_model_create,
            msg_box.id, account_id)
        return web.json_response(api_token_view_model_get.to_dict())

    except JSONDecodeError as e:
        logger.exception(e)
        return web.Response(reason="JSONDecodeError: " + str(e), status=400)


# ----- MESSAGE MANAGEMENT APIs ----- #
async def write_message(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
    db: SQLiteDatabase = app_state.sqlite_db

    # Todo - get the account_id from db and return HTTPNotFound if not found
    account_id = 0
    external_id = request.match_info.get('channelid')
    if not external_id:
        return web.Response(reason="channel id wasn't provided", status=404)

    # Note this bearer token is the channel-specific one
    msg_box_api_token = _try_read_bearer_token(request)
    if not msg_box_api_token:
        return web.Response(reason=errors.NoBearerToken.reason, status=errors.NoBearerToken.status)

    if not _auth_for_channel_token(msg_box_api_token, external_id, msg_box_repository):
        raise web.HTTPUnauthorized

    MAX_MESSAGE_CONTENT_LENGTH = int(os.getenv('MAX_MESSAGE_CONTENT_LENGTH'))

    if request.content_type is None or request.content_type == '':
        return web.Response(reason="missing content type header", status=400)

    content_length = request.content_length if request.content_length else 0

    if content_length == 0:
        return web.Response(reason="payload is empty", status=400)

    if content_length > MAX_MESSAGE_CONTENT_LENGTH:
        logger.info(f"Payload too large to write message to channel {external_id} "
                    f"(payload size: {content_length} bytes, "
                    f"max allowed size: {MAX_MESSAGE_CONTENT_LENGTH} bytes).")
        return web.Response(reason="Payload Too Large", status=web.HTTPRequestEntityTooLarge.status_code)

    # Retrieve token information from identity
    msg_box_api_token_object = msg_box_repository.get_api_token(msg_box_api_token)

    # Retrieve channel data
    msg_box = msg_box_repository.get_msg_box(account_id, external_id)

    body = await request.read()

    # Write message to database
    message = Message(
        msg_box_id=msg_box.id,
        msg_box_api_token_id=msg_box_api_token_object.id,
        content_type=request.content_type,
        payload=body,
        received_ts=datetime.utcnow()
    )
    try:
        result = msg_box_repository.write_message(message)
    except Error as e:
        return web.Response(reason=e.reason, status=e.status)

    if isinstance(result, Error):
        return web.Response(reason=result.reason, status=result.status)
    # else result:
    message_id, msg_box_get_view = result
    logger.info(f"Message {message_id} from api_token_id: {msg_box_api_token_object.id} "
                f"written to channel {external_id}")

    # Send push notification
    notification_new_message_text = os.getenv('NOTIFICATION_TEXT_NEW_MESSAGE', "New message arrived")
    notification = PushNotification(
        msg_box=msg_box,
        notification_new_message_text=notification_new_message_text,
        received_ts=message.received_ts
    )
    app_state.msg_box_new_msg_queue.put((msg_box_api_token_object.id, notification))

    return web.json_response(msg_box_get_view.to_dict())


def _get_messages_head(external_id: str, msg_box_api_token: str,
        msg_box_repository: MsgBoxSQLiteRepository) -> web.Response:
    logger.debug(f"Head called for msg_box: {external_id}.")

    max_sequence = msg_box_repository.get_max_sequence(msg_box_api_token, external_id)
    if max_sequence is None:
        return web.HTTPNotFound()

    max_sequence = str(max_sequence)

    logger.debug(f"Head message sequence of msg_box: {external_id} is {max_sequence}.")
    response_headers = {}
    response_headers.update({'User-Agent': 'ESV-Ref-Server'})
    response_headers.update({'Access-Control-Expose-Headers': 'authorization,etag'})
    response_headers.update({'ETag': max_sequence})
    return web.HTTPOk(headers=response_headers)


def _get_messages(channelid: str, api_token_id: int, onlyunread: bool, accept_type: str,
        msg_box_repository: MsgBoxSQLiteRepository):
    logger.info(f"Get messages for channel_id: {channelid}.")
    # Todo - use a generator here and sequentially write the messages out to a streamed response
    message_list, max_sequence = msg_box_repository.get_messages(api_token_id, onlyunread)
    logger.info(f"Returning {len(message_list)} messages for channel: {channelid}.")
    if accept_type == 'application/octet-stream':
        return web.HTTPNotImplemented()
    else:
        response_headers = {}
        response_headers.update({'User-Agent': 'ESV-Ref-Server'})
        response_headers.update({'Access-Control-Expose-Headers': 'authorization,etag'})
        response_headers.update({'ETag': str(max_sequence)})
        return web.json_response(message_list, status=200, headers=response_headers)


async def get_messages(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
    accept_type = request.headers.get('Accept')

    external_id = request.match_info.get('channelid')
    onlyunread = request.query.get('unread', False)
    if not external_id:
        return web.Response(reason="channel id wasn't provided", status=404)

    # Note this bearer token is the channel-specific one
    msg_box_api_token = _try_read_bearer_token(request)
    if not msg_box_api_token:
        return web.Response(reason=errors.NoBearerToken.reason, status=errors.NoBearerToken.status)

    if not _auth_for_channel_token(msg_box_api_token, external_id, msg_box_repository):
        raise web.HTTPUnauthorized

    if request.method == 'HEAD':
        response = _get_messages_head(external_id, msg_box_api_token, msg_box_repository)
        return response

    # request.method == 'GET'
    msg_box_api_token_obj = msg_box_repository.get_api_token(msg_box_api_token)
    response = _get_messages(external_id, msg_box_api_token_obj.id, onlyunread, accept_type, msg_box_repository)
    return response


async def mark_message_read_or_unread(request: web.Request) -> web.Response:
    try:
        app_state: ApplicationState = request.app['app_state']
        msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
        accept_type = request.headers.get('Accept')

        external_id = request.match_info.get('channelid')
        if not external_id:
            return web.Response(reason="channel id wasn't provided", status=404)

        sequence = request.match_info.get('sequence')
        if not sequence:
            return web.Response(reason="sequence number of message wasn't provided", status=404)

        older = bool(request.query.get('older', False))  # optional - marks all older messages

        # Note this bearer token is the channel-specific one
        msg_box_api_token = _try_read_bearer_token(request)
        if not msg_box_api_token:
            return web.Response(reason=errors.NoBearerToken.reason, status=errors.NoBearerToken.status)

        if not _auth_for_channel_token(msg_box_api_token, external_id, msg_box_repository):
            raise web.HTTPUnauthorized

        body = await request.json()
        set_read_to = body['read']

        logger.info(f"Flagging message sequence {sequence} from msg_box {external_id} "
                    f"{'and all older messages ' if older else ''}"
                    f"as {'read' if set_read_to is True else 'unread'}")
        msg_box_api_token_obj = msg_box_repository.get_api_token(msg_box_api_token)
        if not msg_box_repository.sequence_exists(msg_box_api_token_obj.id, int(sequence)):
            return web.Response(reason="Sequence not found", status=404)

        msg_box_repository.mark_messages(external_id, msg_box_api_token_obj.id, sequence, older, set_read_to)
        return web.HTTPOk()
    except JSONDecodeError as e:
        logger.exception(e)
        return web.Response(reason="JSONDecodeError: " + str(e), status=400)


async def delete_message(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
    accept_type = request.headers.get('Accept')

    account_id = 0
    external_id = request.match_info.get('channelid')
    if not external_id:
        return web.Response(reason="channel id wasn't provided", status=404)

    sequence = request.match_info.get('sequence')
    if not sequence:
        return web.Response(reason="sequence number of message wasn't provided", status=404)

    older = bool(request.query.get('older', False))  # optional - marks all older messages

    # Note this bearer token is the channel-specific one
    msg_box_api_token = _try_read_bearer_token(request)
    if not msg_box_api_token:
        return web.Response(reason=errors.NoBearerToken.reason, status=errors.NoBearerToken.status)

    if not _auth_for_channel_token(msg_box_api_token, external_id, msg_box_repository):
        raise web.HTTPUnauthorized

    logger.info(f"Deleting message sequence: {sequence} in msg_box: {external_id}.")
    msg_box_api_token_obj = msg_box_repository.get_api_token(msg_box_api_token)
    if not msg_box_repository.sequence_exists(msg_box_api_token_obj.id, int(sequence)):
        return web.Response(reason="Sequence not found", status=404)

    message_metadata = msg_box_repository.get_message_metadata(external_id, sequence)
    if not message_metadata:
        logger.error(f"Message metadata not found for sequence: {sequence}, external_id: {external_id} - likely was already deleted")
        return web.Response(reason="message metadata not found - is it deleted already?", status=404)
    msg_box = msg_box_repository.get_msg_box(account_id, external_id)

    min_timestamp = message_metadata.received_ts + timedelta(days=msg_box.min_age_days)
    if datetime.utcnow() < min_timestamp:
        return web.Response(reason=errors.RetentionNotExpired,
                            status=errors.RetentionNotExpired.status)

    count_deleted = msg_box_repository.delete_message(message_metadata.id)
    logger.info(f"Deleted {count_deleted} messages for sequence: {sequence} in msg_box: {external_id}.")
    return web.HTTPOk()


class MsgBoxWebSocket(web.View):
    logger = logging.getLogger("message-box-websocket")

    async def get(self):
        """The communication for this is one-way - for message box notifications only.
        Client messages will be ignored"""
        app_state: 'ApplicationState' = self.request.app['app_state']
        msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
        accept_type = self.request.headers.get('Accept')
        ws = web.WebSocketResponse()
        await ws.prepare(self.request)
        ws_id = str(uuid.uuid4())

        try:
            account_id = 0
            external_id = self.request.match_info.get('channelid')
            if not external_id:
                raise Error(reason="channel id wasn't provided", status=404)

            # Note this bearer token is the channel-specific one
            msg_box_api_token = _try_read_bearer_token(self.request)
            if not msg_box_api_token:
                raise Error(reason=errors.NoBearerToken.reason, status=errors.NoBearerToken.status)

            if not _auth_for_channel_token(msg_box_api_token, external_id, msg_box_repository):
                raise Error(reason="unauthorized", status=web.HTTPUnauthorized.status_code)

            msg_box_external_id = self.request.match_info.get('channelid')
            msg_box = msg_box_repository.get_msg_box(account_id, external_id)
            client = MsgBoxWSClient(
                ws_id=ws_id, websocket=ws,
                msg_box_internal_id=msg_box.id,
                accept_type=accept_type
            )
            app_state.add_msg_box_ws_client(client)
            self.logger.debug('%s connected. host=%s. channel_id=%s, accept_type=%s',
                client.ws_id, self.request.host, msg_box_external_id, accept_type)
            await self._handle_new_connection(client)
            return ws
        except Error as e:
            await ws.send_json(e.to_websocket_dict())
            await ws.close()
        finally:
            if not ws.closed:
                await ws.close()
                self.logger.debug("removing msg box websocket id: %s", ws_id)
                del self.request.app['msg_box_ws_clients'][ws_id]

    async def _handle_new_connection(self, client: MsgBoxWSClient):
        # self.msg_box_ws_clients = self.request.app['msg_box_ws_clients']

        async for msg in client.websocket:
            # Ignore all messages from client
            if msg.type == aiohttp.WSMsgType.text:
                self.logger.debug('%s new message box websocket client sent (message ignored): %s',
                    client.ws_id, msg.data)

            elif msg.type == aiohttp.WSMsgType.error:
                # 'client.websocket.exception()' merely returns ClientWebSocketResponse._exception
                # without a traceback. see aiohttp.ws_client.py:receive for details.
                self.logger.error('ws connection closed with exception %s',
                    client.websocket.exception())

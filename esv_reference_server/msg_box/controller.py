"""
Copyright(c) 2021 Bitcoin Association.
Distributed under the Open BSV software license, see the accompanying file LICENSE
"""

from __future__ import annotations

import logging
import os
import uuid
from dataclasses import asdict
from datetime import datetime, timedelta
from json import JSONDecodeError
from typing import TYPE_CHECKING, Optional, Union, List, Dict, Tuple

import aiohttp
from aiohttp import web
from aiohttp.web_ws import WebSocketResponse

from ..constants import AccountMessageKind
from .. import errors
from ..errors import Error
from .models import MsgBox, Message
from .repositories import MsgBoxSQLiteRepository
from ..types import AccountMessage, ChannelNotification, EndpointInfo, MsgBoxWSClient, \
    PushNotification
from ..utils import _try_read_bearer_token, _auth_ok, _try_read_bearer_token_from_query
from .view_models import RetentionViewModel, MsgBoxViewModelGet, \
    MsgBoxViewModelCreate, MsgBoxViewModelAmend, APITokenViewModelCreate, MessageViewModelGetJSON, \
    MessageViewModelGetBinary

if TYPE_CHECKING:
    from ..server import ApplicationState
    from ..sqlite_db import SQLiteDatabase


logger = logging.getLogger('handlers-peer-channels')


def _auth_for_channel_token(request: web.Request, handler_name: str, token: str, external_id: str,
        msg_box_repository: MsgBoxSQLiteRepository) -> bool:
    token_object = msg_box_repository.get_api_token(token)
    if not token_object:
        raise web.HTTPUnauthorized()

    if token_object.valid_to and datetime.utcnow() > token_object.valid_to:
        raise web.HTTPUnauthorized(reason="token expired")

    if (request.method.lower() == 'post'
            and (handler_name == 'mark_message_read_or_unread' and not token_object.can_read
                 or handler_name != 'mark_message_read_or_unread' and not token_object.can_write)
        or (request.method.lower() == 'delete' and not token_object.can_write)
        or ((request.method.lower() == 'get' or request.method.lower() == 'head')
            and not token_object.can_read)):
        raise web.HTTPUnauthorized()
    logger.debug(f"Request was authenticated as API token: {token}")
    return msg_box_repository.is_authorized_to_msg_box_api_token(external_id, token_object.id)


def _msg_box_get_view(request: web.Request, msg_box: MsgBox) -> MsgBoxViewModelGet:
    API_ROUTE_DEFS: Dict[str, EndpointInfo] = request.app.API_ROUTE_DEFS  # type: ignore
    get_messages_url = API_ROUTE_DEFS['get_messages'].url.format(
        channelid=msg_box.external_id)
    get_messages_href = get_messages_url
    return MsgBoxViewModelGet.from_msg_box(msg_box, href=get_messages_href)


# ----- CHANNEL MANAGEMENT APIs ----- #
async def list_channels(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
    db: SQLiteDatabase = app_state.sqlite_db

    api_key = _try_read_bearer_token(request)
    if not api_key:
        return web.Response(reason=errors.NoBearerToken.reason,
                            status=errors.NoBearerToken.status)

    if not _auth_ok(api_key, db):
        raise web.HTTPUnauthorized

    # Todo - get the account_id from db and return HTTPNotFound if not found
    # Todo - check the account_id against the channel_id to ensure this user
    #  has the required read/write permissions
    account_id = 0
    logger.info(f"Get list of message boxes for accountid: {account_id}.")

    msg_boxes: List[MsgBox] = msg_box_repository.get_msg_boxes(account_id)
    result = []
    for msg_box in msg_boxes:
        msg_box_view_get = _msg_box_get_view(request, msg_box)
        result.append(asdict(msg_box_view_get))
    logger.info(f"Returning {len(msg_boxes)} channels for account_id: {account_id}.")
    return web.json_response(result)


async def get_single_channel_details(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
    db: SQLiteDatabase = app_state.sqlite_db

    api_key = _try_read_bearer_token(request)
    if not api_key:
        return web.Response(reason=errors.NoBearerToken.reason,
                            status=errors.NoBearerToken.status)

    if not _auth_ok(api_key, db):
        raise web.HTTPUnauthorized

    # Todo - get the account_id from db and return HTTPNotFound if not found
    # Todo - check the account_id against the channel_id to ensure this user
    #  has the required read/write permissions
    account_id = 0
    external_id = request.match_info['channelid']

    logger.info(f"Get message box by external_id {external_id} for account(id) {account_id}.")
    msg_box: Optional[MsgBox] = msg_box_repository.get_msg_box(account_id, external_id)
    if not msg_box:
        raise web.HTTPNotFound
    msg_box_view_get = _msg_box_get_view(request, msg_box)
    logger.info(f"Returning message box by external_id: {external_id}.")
    return web.json_response(asdict(msg_box_view_get))


async def update_single_channel_properties(request: web.Request) -> web.Response:
    try:
        app_state: ApplicationState = request.app['app_state']
        msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
        db: SQLiteDatabase = app_state.sqlite_db

        api_key = _try_read_bearer_token(request)
        if not api_key:
            return web.Response(reason=errors.NoBearerToken.reason,
                                status=errors.NoBearerToken.status)

        if not _auth_ok(api_key, db):
            raise web.HTTPUnauthorized

        # Todo - get the account_id from db and return HTTPNotFound if not found
        # Todo - check the account_id against the channel_id to ensure this user
        #  has the required read/write permissions
        account_id = 0
        external_id = request.match_info['channelid']
        body = await request.json()
        _msg_box_view_amend = MsgBoxViewModelAmend(public_read=body['public_read'],
            public_write=body['public_write'], locked=body['locked'])

        logger.info(f"Updating message box by external_id {external_id} "
                    f"for account(id) {account_id}.")
        assert _msg_box_view_amend is not None
        msg_box_view_amend = msg_box_repository.update_msg_box(
            _msg_box_view_amend, external_id)
        if not msg_box_view_amend:
            raise web.HTTPNotFound()
        logger.info(f"Message box with external_id: {external_id} was updated.")
        return web.json_response(data=asdict(msg_box_view_amend))
    except JSONDecodeError as e:
        logger.exception(e)
        return web.Response(reason="JSONDecodeError: " + str(e), status=400)


async def delete_channel(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
    db: SQLiteDatabase = app_state.sqlite_db

    api_key = _try_read_bearer_token(request)
    if not api_key:
        return web.Response(reason=errors.NoBearerToken.reason,
                            status=errors.NoBearerToken.status)

    if not _auth_ok(api_key, db):
        raise web.HTTPUnauthorized

    # Todo - get the account_id from db and return HTTPNotFound if not found
    # Todo - check the account_id against the channel_id to ensure this user
    #  has the required read/write permissions
    account_id = 0
    external_id = request.match_info['channelid']

    logger.info(f"Deleting message box by external_id {external_id} "
                f"for account(id) {account_id}.")
    msg_box_repository.delete_msg_box(external_id)

    logger.info(f"Channel Deleted.")
    raise web.HTTPNoContent()


async def create_new_channel(request: web.Request) -> web.Response:
    try:
        app_state: ApplicationState = request.app['app_state']
        msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
        db: SQLiteDatabase = app_state.sqlite_db

        logger.debug(request.headers)
        api_key = _try_read_bearer_token(request)
        if not api_key:
            return web.Response(reason=errors.NoBearerToken.reason,
                                status=errors.NoBearerToken.status)

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
            return web.Response(reason=errors.RetentionInvalidMinMax.reason,
                                status=errors.RetentionInvalidMinMax.status)

        msg_box_view_create = MsgBoxViewModelCreate.from_request(body)
        msg_box: MsgBox = msg_box_repository.create_message_box(msg_box_view_create,
            account_id)

        msg_box_view_get = _msg_box_get_view(request, msg_box)
        logger.info(f"New message box for account_id {account_id} "
                    f"was created external_id: {msg_box_view_get.id}.")
        return web.json_response(asdict(msg_box_view_get))
    except JSONDecodeError as e:
        logger.exception(e)
        return web.Response(reason="JSONDecodeError: " + str(e), status=400)


async def revoke_selected_token(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
    db: SQLiteDatabase = app_state.sqlite_db

    api_key = _try_read_bearer_token(request)
    if not api_key:
        return web.Response(reason=errors.NoBearerToken.reason,
                            status=errors.NoBearerToken.status)

    if not _auth_ok(api_key, db):
        raise web.HTTPUnauthorized

    # Todo - get the account_id from db and return HTTPNotFound if not found
    # Todo - check the account_id against the channel_id to ensure this user
    #  has the required read/write permissions
    account_id = 0
    _external_id = request.match_info.get('channelid')
    token_id = request.match_info['tokenid']
    msg_box_repository.delete_api_token(int(token_id))
    raise web.HTTPNoContent()


async def get_token_details(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
    db: SQLiteDatabase = app_state.sqlite_db

    api_key = _try_read_bearer_token(request)
    if not api_key:
        return web.Response(reason=errors.NoBearerToken.reason,
                            status=errors.NoBearerToken.status)

    if not _auth_ok(api_key, db):
        raise web.HTTPUnauthorized

    # Todo - get the account_id from db and return HTTPNotFound if not found
    # Todo - check the account_id against the channel_id to ensure this user
    #  has the required read/write permissions
    account_id = 0
    _external_id = request.match_info['channelid']
    token_id = request.match_info['tokenid']

    api_token_view_model_get = msg_box_repository.get_api_token_by_id(int(token_id))
    if not api_token_view_model_get:
        raise web.HTTPNotFound
    return web.json_response(asdict(api_token_view_model_get))


async def get_list_of_tokens(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
    db: SQLiteDatabase = app_state.sqlite_db

    api_key = _try_read_bearer_token(request)
    if not api_key:
        return web.Response(reason=errors.NoBearerToken.reason,
                            status=errors.NoBearerToken.status)

    if not _auth_ok(api_key, db):
        raise web.HTTPUnauthorized

    # Todo - get the account_id from db and return HTTPNotFound if not found
    # Todo - check the account_id against the channel_id to ensure this user
    #  has the required read/write permissions
    account_id = 0
    external_id = request.match_info['channelid']
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
            return web.Response(reason=errors.NoBearerToken.reason,
                                status=errors.NoBearerToken.status)

        if not _auth_ok(api_key, db):
            raise web.HTTPUnauthorized

        # Todo - get the account_id from db and return HTTPNotFound if not found
        # Todo - check the account_id against the channel_id to ensure this user
        #  has the required read/write permissions
        account_id = 0
        external_id = request.match_info['channelid']

        msg_box = msg_box_repository.get_msg_box(account_id, external_id)
        if not msg_box:
            raise web.HTTPNotFound

        body = await request.json()
        api_token_view_model_create = APITokenViewModelCreate(**body)
        api_token_view_model_get = msg_box_repository.create_api_token(api_token_view_model_create,
            msg_box.id, account_id)

        if not api_token_view_model_get:
            raise web.HTTPNotFound()

        return web.json_response(asdict(api_token_view_model_get))

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
        raise web.HTTPNotFound(reason="channel id wasn't provided")

    # Note this bearer token is the channel-specific one
    msg_box_api_token = _try_read_bearer_token(request)  # or can be the account master bearer token
    if not msg_box_api_token:
        return web.Response(reason=errors.NoBearerToken.reason,
                            status=errors.NoBearerToken.status)

    try:
        _auth_for_channel_token(request, 'write_message', msg_box_api_token, external_id,
            msg_box_repository)
    except web.HTTPException as e:
        raise e

    MAX_MESSAGE_CONTENT_LENGTH = int(os.getenv('MAX_MESSAGE_CONTENT_LENGTH', '0'))

    with open(r"c:\data\x.txt", "w+") as f:
        f.write("%s\n" % request.content_type)
    if request.content_type is None or request.content_type == '':
        raise web.HTTPBadRequest(reason="missing content type header")

    content_length = request.content_length if request.content_length else 0

    if content_length == 0:
        raise web.HTTPBadGateway(reason="payload is empty")

    if content_length > MAX_MESSAGE_CONTENT_LENGTH:
        logger.info(f"Payload too large to write message to channel {external_id} "
                    f"(payload size: {content_length} bytes, "
                    f"max allowed size: {MAX_MESSAGE_CONTENT_LENGTH} bytes).")
        return web.Response(reason="Payload Too Large",
                            status=web.HTTPRequestEntityTooLarge.status_code)

    # Retrieve token information from identity
    msg_box_api_token_object = msg_box_repository.get_api_token(msg_box_api_token)
    if not msg_box_api_token_object:
        raise web.HTTPNotFound(reason="peer channel token not found")

    # Retrieve channel data
    msg_box = msg_box_repository.get_msg_box(account_id, external_id)
    if not msg_box:
        raise web.HTTPNotFound(reason="peer channel not found")  # this should never happen

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
    notification_new_message_text = os.getenv('NOTIFICATION_TEXT_NEW_MESSAGE',
                                              'New message arrived')
    notification = PushNotification(
        msg_box=msg_box,
        notification=notification_new_message_text,
    )
    # Per-Channel reference API
    app_state.msg_box_new_msg_queue.put_nowait((msg_box_api_token_object.id, notification))

    # General-Purpose websocket
    msg_box = notification['msg_box']
    result = ChannelNotification(id=msg_box.external_id,
        notification=notification['notification'])
    app_state.account_message_queue.put_nowait(AccountMessage(account_id,
        AccountMessageKind.PEER_CHANNEL_MESSAGE, result))

    return web.json_response(msg_box_get_view.to_dict())


def _get_messages_head(external_id: str, msg_box_api_token: str,
        msg_box_repository: MsgBoxSQLiteRepository) -> None:
    logger.debug(f"Head called for msg_box: {external_id}.")

    seq = msg_box_repository.get_max_sequence(msg_box_api_token, external_id)
    if seq is None:
        raise web.HTTPNotFound()

    max_sequence = str(seq)

    logger.debug(f"Head message sequence of msg_box: {external_id} is {max_sequence}.")
    response_headers = {}
    response_headers.update({'User-Agent': 'ESV-Ref-Server'})
    response_headers.update({'Access-Control-Expose-Headers': 'authorization,etag'})
    response_headers.update({'ETag': str(max_sequence)})
    raise web.HTTPOk(headers=response_headers)


def _get_messages(channelid: str, api_token_id: int, onlyunread: bool, accept_type: str,
        msg_box_repository: MsgBoxSQLiteRepository) \
            -> Tuple[List[Union[MessageViewModelGetJSON, MessageViewModelGetBinary]],
                     Dict[str, str]]:
    logger.info(f"Get messages for channel_id: {channelid}.")
    # Todo - use a generator here and sequentially write the messages out to a streamed response
    result = msg_box_repository.get_messages(api_token_id, onlyunread)
    if result is None:
        raise web.HTTPNotFound(reason="messages not found or not sequenced")

    message_list, max_sequence = result
    logger.info(f"Returning {len(message_list)} messages for channel: {channelid}.")
    if accept_type == 'application/octet-stream':
        raise web.HTTPNotImplemented()
    else:
        response_headers = {}
        response_headers.update({'User-Agent': 'ESV-Ref-Server'})
        response_headers.update({'Access-Control-Expose-Headers': 'authorization,etag'})
        response_headers.update({'ETag': str(max_sequence)})
        return message_list, response_headers


async def get_messages(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
    accept_type = request.headers.get('Accept', 'application/json')

    external_id = request.match_info.get('channelid')
    onlyunread = False
    if request.query.get('unread', False) is True:
        onlyunread = True

    if not external_id:
        return web.Response(reason="channel id wasn't provided", status=404)

    # Note this bearer token is the channel-specific one
    msg_box_api_token = _try_read_bearer_token(request)
    if not msg_box_api_token:
        return web.Response(reason=errors.NoBearerToken.reason,
                            status=errors.NoBearerToken.status)

    try:
        _auth_for_channel_token(request, 'get_messages', msg_box_api_token, external_id,
            msg_box_repository)
    except web.HTTPException as e:
        raise e

    if request.method == 'HEAD':
        try:
            _get_messages_head(external_id, msg_box_api_token, msg_box_repository)
        except (web.HTTPException, web.HTTPOk) as resp:
            raise resp

    # request.method == 'GET'
    msg_box_api_token_obj = msg_box_repository.get_api_token(msg_box_api_token)
    if not msg_box_api_token:
        raise web.HTTPNotFound(reason="peer channel token not found")

    assert msg_box_api_token_obj is not None
    message_list, response_headers = _get_messages(
        external_id, msg_box_api_token_obj.id, onlyunread, accept_type, msg_box_repository)
    return web.json_response(message_list, status=200, headers=response_headers)



async def mark_message_read_or_unread(request: web.Request) -> web.Response:
    try:
        app_state: ApplicationState = request.app['app_state']
        msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
        accept_type = request.headers.get('Accept', 'application/json')

        external_id = request.match_info.get('channelid')
        if not external_id:
            raise web.HTTPNotFound(reason="channel id wasn't provided")

        sequence = request.match_info.get('sequence')
        if not sequence:
            raise web.HTTPNotFound(reason="sequence number of message wasn't provided")

        older = bool(request.query.get('older', False))  # optional - marks all older messages

        # Note this bearer token is the channel-specific one
        msg_box_api_token = _try_read_bearer_token(request)
        if not msg_box_api_token:
            return web.Response(reason=errors.NoBearerToken.reason,
                                status=errors.NoBearerToken.status)

        try:
            _auth_for_channel_token(request, 'mark_message_read_or_unread', msg_box_api_token,
                external_id, msg_box_repository)
        except web.HTTPException as e:
            raise e

        body = await request.json()
        set_read_to = body['read']

        logger.info(f"Flagging message sequence {sequence} from msg_box {external_id} "
                    f"{'and all older messages ' if older else ''}"
                    f"as {'read' if set_read_to is True else 'unread'}")
        msg_box_api_token_obj = msg_box_repository.get_api_token(msg_box_api_token)
        if msg_box_api_token_obj and \
                not msg_box_repository.sequence_exists(msg_box_api_token_obj.id, int(sequence)):
            return web.Response(reason="Sequence not found", status=404)

        assert msg_box_api_token_obj is not None
        msg_box_repository.mark_messages(
            external_id, msg_box_api_token_obj.id, int(sequence), older, set_read_to)
        raise web.HTTPOk()
    except JSONDecodeError as e:
        logger.exception(e)
        return web.Response(reason="JSONDecodeError: " + str(e), status=400)


async def delete_message(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
    accept_type = request.headers.get('Accept', 'application/json')

    account_id = 0
    external_id = request.match_info.get('channelid')
    if not external_id:
        raise web.HTTPNotFound(reason="channel id wasn't provided")

    sequence = request.match_info.get('sequence')
    if not sequence:
        raise web.HTTPNotFound(reason="sequence number of message wasn't provided")

    # Note this bearer token is the channel-specific one
    msg_box_api_token = _try_read_bearer_token(request)
    if not msg_box_api_token:
        return web.Response(reason=errors.NoBearerToken.reason,
                            status=errors.NoBearerToken.status)

    try:
        _auth_for_channel_token(request, 'delete_message', msg_box_api_token, external_id,
            msg_box_repository)
    except web.HTTPException as e:
        raise e

    logger.info(f"Deleting message sequence: {sequence} in msg_box: {external_id}.")
    msg_box_api_token_obj = msg_box_repository.get_api_token(msg_box_api_token)
    if msg_box_api_token_obj and \
            not msg_box_repository.sequence_exists(msg_box_api_token_obj.id, int(sequence)):
        raise web.HTTPNotFound(reason="sequence not found")

    message_metadata = msg_box_repository.get_message_metadata(external_id, int(sequence))
    if not message_metadata:
        logger.error(f"Message metadata not found for sequence: {sequence}, "
                     f"external_id: {external_id} - likely was already deleted")
        raise web.HTTPNotFound(reason="message metadata not found - is it deleted already?")
    msg_box = msg_box_repository.get_msg_box(account_id, external_id)
    if not msg_box:
        raise web.HTTPNotFound(reason="message box not found")  # this should never happen

    min_timestamp = message_metadata.received_ts + timedelta(days=msg_box.min_age_days)
    if datetime.utcnow() < min_timestamp:
        return web.Response(reason=errors.RetentionNotExpired.reason,
                            status=errors.RetentionNotExpired.status)

    count_deleted = msg_box_repository.delete_message(message_metadata.id)
    logger.info(f"Deleted {count_deleted} messages for sequence: {sequence} "
                f"in msg_box: {external_id}.")
    raise web.HTTPOk()


class MsgBoxWebSocket(web.View):
    logger = logging.getLogger("message-box-websocket")

    async def get(self) -> Union[WebSocketResponse, web.Response]:
        """The communication for this is one-way - for message box notifications only.
        Client messages will be ignored"""
        app_state: 'ApplicationState' = self.request.app['app_state']
        msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
        ws_id = str(uuid.uuid4())

        external_id = self.request.match_info.get('channelid')
        if not external_id:
            raise Error(reason="channel id wasn't provided", status=404)

        # Note this bearer token is the channel-specific one
        msg_box_api_token = _try_read_bearer_token_from_query(self.request)
        if not msg_box_api_token:
            raise Error(reason=errors.NoBearerToken.reason,
                        status=errors.NoBearerToken.status)

        account_id = 0
        try:
            _auth_for_channel_token(self.request, 'MsgBoxWebSocket', msg_box_api_token,
                                    external_id, msg_box_repository)
        except web.HTTPException as e:
            return web.Response(reason="Unauthorized - Invalid Bearer Token", status=401)

        msg_box_external_id = self.request.match_info.get('channelid')
        msg_box = msg_box_repository.get_msg_box(account_id, external_id)
        if not msg_box:
            return web.Response(reason="peer channel not found for external id: %s" % external_id,
                status=404)

        ws = web.WebSocketResponse()
        await ws.prepare(self.request)
        client = MsgBoxWSClient(
            ws_id=ws_id, websocket=ws,
            msg_box_internal_id=msg_box.id,
        )
        app_state.add_msg_box_ws_client(client)
        self.logger.debug('%s connected. host=%s. channel_id=%s',
            client.ws_id, self.request.host, msg_box_external_id)

        try:
            await self._handle_new_connection(client)
            return ws
        except Error as e:
            return web.Response(reason=e.reason, status=e.status)
        finally:
            if not ws.closed:
                await ws.close()

            self.logger.debug("removing msg box websocket id: %s", ws_id)
            app_state.remove_msg_box_ws_client(ws_id)

    async def _handle_new_connection(self, client: MsgBoxWSClient) -> None:
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

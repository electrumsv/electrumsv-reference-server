"""
Copyright(c) 2021 Bitcoin Association.
Distributed under the Open BSV software license, see the accompanying file LICENSE
"""

from __future__ import annotations

import base64
import time
from dataclasses import asdict
from datetime import timedelta, datetime, timezone
from http import HTTPStatus
from json import JSONDecodeError
import logging
import os
from typing import cast, TYPE_CHECKING, Optional, Union
import uuid

import aiohttp
from aiohttp import web
from aiohttp.web_ws import WebSocketResponse

from ..constants import AccountMessageKind
from ..errors import APIErrors
from .. import sqlite_db
from ..types import AccountMessage, ChannelNotification, MsgBoxWSClient, \
    PushNotification
from ..utils import _try_read_bearer_token

from .models import Message, MsgBox, MsgBoxAPIToken
from .repositories import MsgBoxSQLiteRepository, PeerChannelMessageWriteError
from .view_models import RetentionViewModel, MsgBoxViewModelGet, \
    MsgBoxViewModelCreate, MsgBoxViewModelAmend, APITokenViewModelCreate

if TYPE_CHECKING:
    from ..application_state import ApplicationState


logger = logging.getLogger('handlers-peer-channels')


def _auth_for_channel_token(request: web.Request,
        handler_name: str, token: str, external_id: str,
        msg_box_repository: MsgBoxSQLiteRepository) -> tuple[int, MsgBoxAPIToken]:
    token_row = msg_box_repository.get_api_token(token)
    if token_row is None:
        raise web.HTTPUnauthorized()

    if token_row.valid_to and datetime.now(tz=timezone.utc) > token_row.valid_to:
        assert token_row.valid_to.tzinfo == timezone.utc
        raise web.HTTPUnauthorized(reason=f"{APIErrors.PEER_CHANNEL_TOKEN_EXPIRED}: "
                                          "Peer channel token expired.")

    if (request.method.lower() == 'post'
            and (handler_name == 'mark_message_read_or_unread' and not token_row.can_read
                 or handler_name != 'mark_message_read_or_unread' and not token_row.can_write)
        or (request.method.lower() == 'delete' and not token_row.can_write)
        or ((request.method.lower() == 'get' or request.method.lower() == 'head')
            and not token_row.can_read)):
        raise web.HTTPUnauthorized()
    logger.debug("Checking per-channel API token authentication: %s", token)
    internal_message_box_id = msg_box_repository.get_api_token_authorization_data_for_msg_box(
        external_id, token_row.id)
    if internal_message_box_id is None:
        raise web.HTTPUnauthorized()
    return internal_message_box_id, token_row


def _msg_box_get_view(request: web.Request, msg_box: MsgBox) -> MsgBoxViewModelGet:
    app_state: ApplicationState = request.app['app_state']
    # NOTE(hardcoded-url) Update this if updating the server URL.
    href = f"http://{app_state.external_host}:{app_state.external_port}"+ \
        f"/api/v1/channel/{msg_box.external_id}"
    return MsgBoxViewModelGet.from_msg_box(msg_box, href=href)


# ----- CHANNEL MANAGEMENT APIs ----- #
async def list_channels(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository

    api_key = _try_read_bearer_token(request)
    if not api_key:
        raise web.HTTPBadRequest(reason="No 'Bearer' authentication.")

    account_id, _account_flags = sqlite_db.get_account_id_for_api_key(
        app_state.database_context, api_key)
    if account_id is None:
        raise web.HTTPUnauthorized

    logger.info("Get list of message boxes for accountid: %s", account_id)

    msg_boxes: list[MsgBox] = msg_box_repository.get_msg_boxes(account_id)
    result = []
    for msg_box in msg_boxes:
        msg_box_view_get = _msg_box_get_view(request, msg_box)
        result.append(asdict(msg_box_view_get))
    logger.info("Returning %d channels for account_id: %s", len(msg_boxes), account_id)
    return web.json_response(result)


async def get_single_channel_details(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository

    api_key = _try_read_bearer_token(request)
    if not api_key:
        raise web.HTTPBadRequest(reason="No 'Bearer' authentication.")

    account_id, _account_flags = sqlite_db.get_account_id_for_api_key(
        app_state.database_context, api_key)
    if account_id is None:
        raise web.HTTPUnauthorized

    # Todo - check the account_id against the channel_id to ensure this user
    #  has the required read/write permissions
    external_id = request.match_info['channelid']

    logger.info("Get message box by external_id %s for account(id) %s", external_id, account_id)
    msg_box: Optional[MsgBox] = msg_box_repository.get_msg_box(account_id, external_id)
    if not msg_box:
        raise web.HTTPNotFound
    msg_box_view_get = _msg_box_get_view(request, msg_box)
    logger.info("Returning message box by external_id: %s", external_id)
    return web.json_response(asdict(msg_box_view_get))


async def update_single_channel_properties(request: web.Request) -> web.Response:
    try:
        app_state: ApplicationState = request.app['app_state']
        msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository

        api_key = _try_read_bearer_token(request)
        if not api_key:
            raise web.HTTPBadRequest(reason="No 'Bearer' authentication.")

        account_id, _account_flags = sqlite_db.get_account_id_for_api_key(
            app_state.database_context, api_key)
        if account_id is None:
            raise web.HTTPUnauthorized

        # Todo - get the account_id from db and return HTTPNotFound if not found
        # Todo - check the account_id against the channel_id to ensure this user
        #  has the required read/write permissions
        external_id = request.match_info['channelid']
        body = await request.json()
        _msg_box_view_amend = MsgBoxViewModelAmend(public_read=body['public_read'],
            public_write=body['public_write'], locked=body['locked'])

        logger.info("Updating message box by external_id %s for account(id) %s.", external_id,
            account_id)
        assert _msg_box_view_amend is not None
        msg_box_view_amend = msg_box_repository.update_msg_box(
            _msg_box_view_amend, external_id)
        if not msg_box_view_amend:
            raise web.HTTPNotFound()
        logger.info("Message box with external_id: %s was updated", external_id)
        return web.json_response(data=asdict(msg_box_view_amend))
    except JSONDecodeError:
        logger.exception("bad request body, invalid JSON")
        raise web.HTTPBadRequest(reason="bad request body, invalid JSON")


async def delete_channel(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository

    api_key = _try_read_bearer_token(request)
    if not api_key:
        raise web.HTTPBadRequest(reason="No 'Bearer' authentication.")

    account_id, _account_flags = sqlite_db.get_account_id_for_api_key(
        app_state.database_context, api_key)
    if account_id is None:
        raise web.HTTPUnauthorized

    # Todo - get the account_id from db and return HTTPNotFound if not found
    # Todo - check the account_id against the channel_id to ensure this user
    #  has the required read/write permissions
    assert account_id is not None
    external_id = request.match_info['channelid']

    logger.info("Deleting message box by external_id %s for account(id) %s", external_id,
        account_id)
    msg_box_repository.delete_msg_box(external_id)

    logger.info("Channel Deleted")
    raise web.HTTPNoContent()


async def create_new_channel(request: web.Request) -> web.Response:
    try:
        app_state: ApplicationState = request.app['app_state']
        msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository

        logger.debug(request.headers)
        api_key = _try_read_bearer_token(request)
        if not api_key:
            raise web.HTTPBadRequest(reason="No 'Bearer' authentication.")

        account_id, _account_flags = sqlite_db.get_account_id_for_api_key(
            app_state.database_context, api_key)
        if account_id is None:
            raise web.HTTPUnauthorized

        # Todo - get the account_id from db and return HTTPNotFound if not found
        # Todo - check the account_id against the channel_id to ensure this user
        #  has the required read/write permissions

        logger.info("Creating new message box for account_id: %s", account_id)
        body = await request.json()
        retention_view_model = RetentionViewModel(**body['retention'])
        if not retention_view_model.is_valid():
            raise web.HTTPBadRequest(reason=f"{APIErrors.RETENTION_INVALID_MIN_MAX}: "
                                            "Invalid retention minimum or maximum.")

        msg_box_view_create = MsgBoxViewModelCreate.from_request(body)
        msg_box: MsgBox = msg_box_repository.create_message_box(msg_box_view_create,
            account_id)

        msg_box_view_get = _msg_box_get_view(request, msg_box)
        logger.info("New message box for account_id %s was created external_id: %s",
            account_id, msg_box_view_get.id)
        return web.json_response(asdict(msg_box_view_get))
    except JSONDecodeError:
        logger.exception("bad request body, invalid JSON")
        raise web.HTTPBadRequest(reason="bad request body, invalid JSON")


async def revoke_selected_token(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository

    api_key = _try_read_bearer_token(request)
    if not api_key:
        raise web.HTTPBadRequest(reason="No 'Bearer' authentication.")

    account_id, _account_flags = sqlite_db.get_account_id_for_api_key(
        app_state.database_context, api_key)
    if account_id is None:
        raise web.HTTPUnauthorized

    # Todo - get the account_id from db and return HTTPNotFound if not found
    # Todo - check the account_id against the channel_id to ensure this user
    #  has the required read/write permissions
    _external_id = request.match_info.get('channelid')
    token_id = request.match_info['tokenid']
    msg_box_repository.delete_api_token(int(token_id))
    raise web.HTTPNoContent()


async def get_token_details(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository

    api_key = _try_read_bearer_token(request)
    if not api_key:
        raise web.HTTPBadRequest(reason="No 'Bearer' authentication.")

    account_id, _account_flags = sqlite_db.get_account_id_for_api_key(
        app_state.database_context, api_key)
    if account_id is None:
        raise web.HTTPUnauthorized

    # Todo - get the account_id from db and return HTTPNotFound if not found
    # Todo - check the account_id against the channel_id to ensure this user
    #  has the required read/write permissions
    _external_id = request.match_info['channelid']
    token_id = request.match_info['tokenid']

    api_token_view_model_get = msg_box_repository.get_api_token_by_id(int(token_id))
    if not api_token_view_model_get:
        raise web.HTTPNotFound
    return web.json_response(asdict(api_token_view_model_get))


async def get_list_of_tokens(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository

    api_key = _try_read_bearer_token(request)
    if not api_key:
        raise web.HTTPBadRequest(reason="No 'Bearer' authentication.")

    account_id, _account_flags = sqlite_db.get_account_id_for_api_key(
        app_state.database_context, api_key)
    if account_id is None:
        raise web.HTTPUnauthorized

    # Todo - get the account_id from db and return HTTPNotFound if not found
    # Todo - check the account_id against the channel_id to ensure this user
    #  has the required read/write permissions
    external_id = request.match_info['channelid']
    token = request.query.get('token')

    list_api_token_view_model_get = msg_box_repository.get_api_tokens(external_id, token)
    if not list_api_token_view_model_get:
        raise web.HTTPNotFound
    return web.json_response(list_api_token_view_model_get)


async def create_new_token_for_channel(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository

    api_key = _try_read_bearer_token(request)
    if not api_key:
        raise web.HTTPBadRequest(reason="No 'Bearer' authentication.")

    account_id, _account_flags = sqlite_db.get_account_id_for_api_key(
        app_state.database_context, api_key)
    if account_id is None:
        raise web.HTTPUnauthorized

    external_id = request.match_info['channelid']

    msg_box = msg_box_repository.get_msg_box(account_id, external_id)
    if msg_box is None:
        raise web.HTTPNotFound

    try:
        body = await request.json()
    except JSONDecodeError as e:
        logger.exception("failed getting json from request")
        raise web.HTTPBadRequest(reason="bad request body, invalid JSON")

    api_token_view_model_create = APITokenViewModelCreate(**body)
    api_token_view_model_get = msg_box_repository.create_api_token(api_token_view_model_create,
        msg_box.id, account_id)
    if api_token_view_model_get is None:
        raise web.HTTPNotFound()

    return web.json_response(asdict(api_token_view_model_get))


# ----- MESSAGE MANAGEMENT APIs ----- #
async def write_message(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository

    external_id = request.match_info.get('channelid')
    if not external_id:
        raise web.HTTPNotFound(reason=f"{APIErrors.MISSING_PATH_PARAMETER}: "
                                      "Channel ID path parameter not provided.")
    # Todo - get the account_id from db and return HTTPNotFound if not found
    auth_string = request.headers.get('Authorization', None)
    if auth_string is None or not auth_string.startswith("Bearer "):
        raise web.HTTPBadRequest()

    api_key = auth_string[7:]
    # First check the account master api key.
    # account_id, account_flags = sqlite_db.get_account_id_for_api_key(app_state.database_context,
    #     api_key)
    # if account_id is None:
    if True:
        # This will raise an unauthorised response exception if the token is invalid for the
        # given message box represented by `external_id`.
        internal_message_box_id, api_token_row =_auth_for_channel_token(request,
            'write_message', api_key, external_id, msg_box_repository)
        message_box_row = msg_box_repository.get_message_box_by_id(internal_message_box_id)
        assert message_box_row is not None
    # else:
    #     msg_box = msg_box_repository.get_msg_box(account_id, external_id)
    #     if msg_box is None:
    #         raise web.HTTPNotFound(reason="peer channel not found")

    MAX_MESSAGE_CONTENT_LENGTH = int(os.getenv('MAX_MESSAGE_CONTENT_LENGTH', '0'))

    if request.content_type is None or request.content_type == '':
        raise web.HTTPBadRequest(reason=f"{APIErrors.MISSING_HEADER}: "
                                        "Missing content-type header.")

    content_length = request.content_length if request.content_length else 0

    if content_length == 0:
        raise web.HTTPBadRequest(reason="Payload is empty")

    if content_length > MAX_MESSAGE_CONTENT_LENGTH:
        logger.info("Payload too large to write message to channel %s (payload size: %d bytes, "
            "max allowed size: %d bytes).", external_id, content_length, MAX_MESSAGE_CONTENT_LENGTH)
        raise web.HTTPRequestEntityTooLarge(reason=f"{APIErrors.PAYLOAD_TOO_LARGE}: "
                                                   "Payload is too large.",
                                            max_size=MAX_MESSAGE_CONTENT_LENGTH,
                                            actual_size=content_length)

    body = await request.read()

    if request.content_type == "application/json":
        body = base64.b64encode(body).decode().encode('utf-8')

    # Write message to database
    message = Message(
        msg_box_id=message_box_row.id,
        msg_box_api_token_id=api_token_row.id,
        content_type=request.content_type,
        payload=body,
        received_ts=int(time.time())
    )
    try:
        result = msg_box_repository.write_message(message)
    except PeerChannelMessageWriteError as exc:
        if exc.code == APIErrors.CHANNEL_LOCKED:
            raise web.HTTPBadRequest(reason=f"{APIErrors.CHANNEL_LOCKED}: "
                                            "Channel is locked. Write failed.")
        elif exc.code == APIErrors.SEQUENCING_FAILURE:
            raise web.HTTPBadRequest(reason=f"{APIErrors.SEQUENCING_FAILURE}: "
                                            "Sequencing failure. This channel still "
                                            "has unread messages. Write failed.")
        elif exc.code == APIErrors.DATABASE_WRITE_FAILURE:
            return web.Response(reason=f"{APIErrors.DATABASE_WRITE_FAILURE}: "
                                       "Database insertion failed unexpectedly - Try again later.",
                                status=HTTPStatus.INTERNAL_SERVER_ERROR)
        else:
            raise web.HTTPInternalServerError()

    assert result is not None
    message_id, msg_box_get_view = result
    logger.info("Message %s from api_token_id: %s written to channel %s", message_id,
        api_token_row.id, external_id)

    # Send push notification
    notification_new_message_text = os.getenv('NOTIFICATION_TEXT_NEW_MESSAGE',
                                              'New message arrived')
    notification = PushNotification(
        msg_box=message_box_row,
        notification=notification_new_message_text,
    )
    # Per-Channel reference API
    app_state.msg_box_new_msg_queue.put_nowait((api_token_row.id, notification))

    # General-Purpose websocket
    channel_msg = ChannelNotification(id=message_box_row.external_id,
        notification=notification['notification'])
    app_state.account_message_queue.put_nowait(AccountMessage(message_box_row.account_id,
        AccountMessageKind.PEER_CHANNEL_MESSAGE, channel_msg))

    return web.json_response(msg_box_get_view.to_dict())


async def get_messages(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
    accept_type = request.headers.get('Accept', 'application/json')
    if accept_type not in ('application/json', "*/*"):
        raise web.HTTPBadRequest(reason=f"Unsupported 'accept' header mime type '{accept_type}'.")

    external_id = request.match_info.get('channelid')
    if external_id is None:
        raise web.HTTPNotFound(reason=f"{APIErrors.MISSING_PATH_PARAMETER}: "
                                      "Channel ID not provided.")

    onlyunread = False
    if request.query.get('unread', "false") == "true":
        onlyunread = True

    # Note this bearer token is the channel-specific one
    msg_box_api_token = _try_read_bearer_token(request)
    if msg_box_api_token is None:
        raise web.HTTPBadRequest(reason="No 'Bearer' authentication.")

    _auth_for_channel_token(request, 'get_messages', msg_box_api_token, external_id,
        msg_box_repository)

    if request.method == 'HEAD':
        logger.debug("Head called for msg_box: %s", external_id)

        max_sequence = msg_box_repository.get_max_sequence(msg_box_api_token, external_id)
        if max_sequence is None:
            raise web.HTTPNotFound()

        logger.debug("Head max sequence of msg_box: %s is %s", external_id, max_sequence)
        response_headers = {
            'User-Agent': 'ESV-Ref-Server',
            'Access-Control-Expose-Headers': 'authorization,etag',
            'ETag': str(max_sequence),
        }
        return web.Response(headers=response_headers)

    assert request.method == 'GET'

    msg_box_api_token_obj = msg_box_repository.get_api_token(msg_box_api_token)
    if not msg_box_api_token:
        raise web.HTTPNotFound(reason=f"{APIErrors.PEER_CHANNEL_TOKEN_NOT_FOUND}: "
                                      "Peer channel token not found.")

    assert msg_box_api_token_obj is not None
    logger.info("Get messages for channel_id: %s", external_id)
    # Todo - use a generator here and sequentially write the messages out to a streamed response
    result = msg_box_repository.get_messages(msg_box_api_token_obj.id, onlyunread)
    if result is None:
        raise web.HTTPNotFound(reason=f"{APIErrors.MESSAGES_NOT_FOUND}: "
                                      "Messages not found or not sequenced.")

    message_list, max_sequence2 = result
    logger.info("Returning %d messages for channel: %s", len(message_list), external_id)

    response_headers = {
        'User-Agent': 'ESV-Ref-Server',
        'Access-Control-Expose-Headers': 'authorization,etag',
        'ETag': str(max_sequence2),
    }
    return web.json_response(message_list, headers=response_headers)



async def mark_message_read_or_unread(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository

    external_id = request.match_info.get('channelid')
    if not external_id:
        raise web.HTTPNotFound(reason=f"{APIErrors.MISSING_PATH_PARAMETER}: "
                                      "Channel ID path parameter not provided.")

    sequence = request.match_info.get('sequence')
    if not sequence:
        raise web.HTTPNotFound(reason=f"{APIErrors.SEQUENCE_NUMBER_NOT_PROVIDED}: "
                                      "Sequence number not provided.")

    older = request.query.get('older', "false") == "true"  # optional - marks all older messages

    # Note this bearer token is the channel-specific one
    msg_box_api_token = _try_read_bearer_token(request)
    if not msg_box_api_token:
        raise web.HTTPBadRequest(reason="No 'Bearer' authentication.")

    try:
        _auth_for_channel_token(request,
            'mark_message_read_or_unread', msg_box_api_token, external_id, msg_box_repository)
    except web.HTTPException as e:
        raise e

    try:
        body = await request.json()
    except JSONDecodeError:
        logger.exception("bad request body, invalid JSON")
        raise web.HTTPBadRequest(reason="bad request body, invalid JSON")

    set_read_to = cast(bool, body['read'])

    logger.info("Flagging message sequence %s from msg_box %s (older=%s, read=%s)",
        sequence, external_id, older, set_read_to)
    msg_box_api_token_obj = msg_box_repository.get_api_token(msg_box_api_token)
    assert msg_box_api_token_obj is not None
    if not msg_box_repository.sequence_exists(msg_box_api_token_obj.id, int(sequence)):
        raise web.HTTPNotFound(reason=f"{APIErrors.SEQUENCE_NUMBER_NOT_FOUND}: "
                                      "Sequence number not found.")

    msg_box_repository.mark_messages(
        external_id, msg_box_api_token_obj.id, int(sequence), older, set_read_to)
    raise web.HTTPOk()


async def delete_message(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
    accept_type = request.headers.get('Accept', 'application/json')

    auth_string = request.headers.get('Authorization', None)
    if auth_string is None or not auth_string.startswith("Bearer "):
        raise web.HTTPBadRequest()

    external_id = request.match_info.get('channelid')
    if not external_id:
        raise web.HTTPNotFound(reason=f"{APIErrors.MISSING_PATH_PARAMETER}: "
                                      "Channel ID path parameter not provided.")

    sequence = request.match_info.get('sequence')
    if not sequence:
        raise web.HTTPNotFound(reason=f"{APIErrors.SEQUENCE_NUMBER_NOT_PROVIDED}: "
                                      "Sequence number not provided.")

    # Note this bearer token is the channel-specific one
    msg_box_api_token = _try_read_bearer_token(request)
    if not msg_box_api_token:
        raise web.HTTPBadRequest(reason="No 'Bearer' authentication.")

    try:
        internal_message_box_id, channel_token = _auth_for_channel_token(request, 'delete_message',
            msg_box_api_token, external_id, msg_box_repository)
    except web.HTTPException as e:
        raise e

    logger.info("Deleting message sequence: %s in msg_box: %s", sequence, external_id)
    if not msg_box_repository.sequence_exists(channel_token.id, int(sequence)):
        raise web.HTTPNotFound(reason=f"{APIErrors.SEQUENCE_NUMBER_NOT_FOUND}: "
                                      "Sequence number not found.")

    message_metadata = msg_box_repository.get_message_metadata(external_id, int(sequence))
    if not message_metadata:
        raise web.HTTPNotFound(reason=f"{APIErrors.MESSAGE_METADATA_NOT_FOUND}: "
                                      "Message metadata not found.")

    msg_box = msg_box_repository.get_message_box_by_id(internal_message_box_id)
    if not msg_box:
        # this should never happen
        raise web.HTTPNotFound(reason=f"{APIErrors.MESSAGE_BOX_NOT_FOUND}: "
                                      f"Peer channel '{external_id}' not found.")

    min_timestamp = message_metadata.received_ts + timedelta(days=msg_box.min_age_days)
    if datetime.now(tz=timezone.utc) < min_timestamp:
        assert min_timestamp.tzinfo == timezone.utc
        raise web.HTTPBadRequest(reason=f"{APIErrors.RETENTION_NOT_YET_EXPIRED}: "
                                        "Retention period has not yet expired.")

    count_deleted = msg_box_repository.delete_message(message_metadata.id)
    logger.info("Deleted %s messages for sequence: %s in msg_box: %s", count_deleted, sequence,
        external_id)
    raise web.HTTPOk()


class MsgBoxWebSocket(web.View):
    logger = logging.getLogger("message-box-websocket")

    async def get(self) -> Union[WebSocketResponse, web.Response]:
        """The communication for this is one-way - for message box notifications only.
        Client messages will be ignored"""
        app_state: 'ApplicationState' = self.request.app['app_state']
        msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
        ws_id = str(uuid.uuid4())

        external_message_box_id = self.request.match_info.get('channelid')
        if not external_message_box_id:
            raise web.HTTPNotFound(reason=f"{APIErrors.MISSING_PATH_PARAMETER}: "
                                          "Channel ID path parameter not provided.")

        # Note this bearer token is the channel-specific one
        channel_api_key = self.request.query.get('token', None)
        if channel_api_key is None:
            raise web.HTTPBadRequest(reason=f"{APIErrors.MISSING_QUERY_PARAM}: "
                                            "Missing 'token' query parameter "
                                            "(requires master bearer token).")

        try:
            internal_message_box_id, channel_token = _auth_for_channel_token(self.request,
                'MsgBoxWebSocket', channel_api_key, external_message_box_id, msg_box_repository)
        except web.HTTPException:
            raise web.HTTPUnauthorized(reason=f"{APIErrors.INVALID_BEARER_TOKEN}: "
                                              f"Unauthorized - invalid Bearer Token")

        ws = web.WebSocketResponse()
        await ws.prepare(self.request)
        client = MsgBoxWSClient(
            ws_id=ws_id, websocket=ws,
            msg_box_internal_id=internal_message_box_id,
        )
        app_state.add_msg_box_ws_client(client)
        self.logger.debug('%s connected. host=%s. channel_id=%s',
            client.ws_id, self.request.host, external_message_box_id)

        try:
            await self._handle_new_connection(client)
            return ws
        except Exception:
            return web.Response(reason="Internal server error", status=500)
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

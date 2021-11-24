from __future__ import annotations

import logging
from json import JSONDecodeError
from typing import TYPE_CHECKING, Optional

from aiohttp import web

from esv_reference_server import errors
from esv_reference_server.msg_box.models import MsgBox
from esv_reference_server.msg_box.repositories import MsgBoxSQLiteRepository
from esv_reference_server.msg_box.view_models import RetentionViewModel, MsgBoxViewModelGet, \
    MsgBoxViewModelCreate, MsgBoxViewModelAmend, APITokenViewModelCreate

if TYPE_CHECKING:
    from esv_reference_server.server import ApplicationState
    from esv_reference_server.sqlite_db import SQLiteDatabase


logger = logging.getLogger('handlers-peer-channels')


def _verify_token(request: web.Request, sqlite_db: SQLiteDatabase):
    auth_string = request.headers.get('Authorization', None)
    if auth_string is not None:
        if not auth_string.startswith("Bearer "):
            raise ValueError("Invalid API key")

        api_key = auth_string[7:]
        return api_key


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

    api_token_view_model_get = msg_box_repository.get_api_token(token_id)
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
    return web.HTTPNotImplemented()


def _get_messages_head(channelid: str, api_key: str, sqlite_db: SQLiteDatabase) -> web.Response:
    logger.debug(f"Head called for channel(id): {channelid}.")

    max_sequence = sqlite_db.get_max_sequence(api_key, channelid)
    if not max_sequence:
        return web.HTTPNotFound()

    logger.debug(f"Head message sequence of channel {channelid} is {max_sequence}.")
    response_headers = {}
    response_headers.update({'User-Agent': 'ESV-Ref-Server'})
    response_headers.update({'Access-Control-Expose-Headers': 'authorization,etag'})
    response_headers.update({'ETag': max_sequence})
    return web.HTTPOk(headers=response_headers)


def _get_messages(channelid: str, api_key: str, unread: bool, accept_type: str,
        sqlite_db: SQLiteDatabase):
    logger.info(f"Get messages for channel_id: {channelid}.")
    message_list, max_sequence = sqlite_db.get_messages(api_key, channelid, unread)
    logger.info(f"Returning {len(message_list)} messages for channel: {channelid}.")
    if accept_type == 'application/json':
        response_headers = {}
        response_headers.update({'User-Agent': 'ESV-Ref-Server'})
        response_headers.update({'Access-Control-Expose-Headers': 'authorization,etag'})
        response_headers.update({'ETag': max_sequence})
        return web.json_response(message_list, status=200, headers=response_headers)
    else:
        return web.HTTPUnsupportedMediaType()


async def get_messages(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    sqlite_db: SQLiteDatabase = app_state.sqlite_db
    accept_type = request.headers.get('Accept')
    channelid = request.match_info.get('channelid')
    unread = request.query.get('unread', False)

    try:
        api_key = _verify_token(request, sqlite_db)
        account_id = sqlite_db.get_account_id_for_api_key(api_key)
    except ValueError:
        return web.HTTPUnauthorized()

    if request.method == 'HEAD':
        response = _get_messages_head(channelid, api_key, sqlite_db)
        return response

    # request.method == 'GET'
    response = _get_messages(channelid, api_key, unread, accept_type, sqlite_db)
    return response


async def mark_message_read_or_unread(request: web.Request) -> web.Response:
    return web.HTTPNotImplemented()


async def delete_message(request: web.Request) -> web.Response:
    return web.HTTPNotImplemented()


# ----- NOTIFICATION & PUSH NOTIFICATION API ----- #
async def subscribe_to_push_notifications(request: web.Request) -> web.Response:
    return web.HTTPNotImplemented()

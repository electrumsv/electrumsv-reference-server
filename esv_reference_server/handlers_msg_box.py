from __future__ import annotations

import os
import logging
from typing import Any, Dict, Optional, TYPE_CHECKING

import aiohttp
from aiohttp import web

if TYPE_CHECKING:
    from .server import ApplicationState
    from .sqlite_db import SQLiteDatabase


logger = logging.getLogger('handlers-peer-channels')


def _verify_token(request: web.Request, sqlite_db: SQLiteDatabase):
    auth_string = request.headers.get('Authorization', None)
    if auth_string is not None:
        if not auth_string.startswith("Bearer "):
            raise ValueError("Invalid API key")

        api_key = auth_string[7:]
        return api_key

# ----- CHANNEL MANAGEMENT APIs ----- #
async def list_channels(request: web.Request) -> web.Response:
    client_session: aiohttp.ClientSession = request.app['client_session']
    app_state: ApplicationState = request.app['app_state']
    sqlite_db: SQLiteDatabase = app_state.sqlite_db
    try:
        api_key = _verify_token(request, sqlite_db)
        account_id = sqlite_db.get_account_id_for_api_key(api_key)
    except ValueError:
        return web.HTTPUnauthorized()


async def get_single_channel_details(request: web.Request) -> web.Response:
    client_session: aiohttp.ClientSession = request.app['client_session']
    app_state: ApplicationState = request.app['app_state']


async def update_single_channel_properties(request: web.Request) -> web.Response:
    return web.HTTPNotImplemented()


async def delete_channel(request: web.Request) -> web.Response:
    return web.HTTPNotImplemented()


async def create_new_channel(request: web.Request) -> web.Response:
    return web.HTTPNotImplemented()


async def get_token_details(request: web.Request) -> web.Response:
    return web.HTTPNotImplemented()


async def revoke_selected_token(request: web.Request) -> web.Response:
    return web.HTTPNotImplemented()


async def get_list_of_tokens(request: web.Request) -> web.Response:
    return web.HTTPNotImplemented()


async def create_new_token_for_channel(request: web.Request) -> web.Response:
    return web.HTTPNotImplemented()


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

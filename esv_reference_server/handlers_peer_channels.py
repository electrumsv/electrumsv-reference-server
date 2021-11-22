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

    # Todo - app_state.peer_channel_account_id change to the user's account_id based on
    #  Bearer token linkage in SQLiteDB
    url_to_fetch = f"{app_state.peer_channels_url}/api/v1/account/" \
        f"{app_state.peer_channel_account_id}/channel/list"
    request_headers = {'Accept': 'application/json'}
    async with client_session.get(url_to_fetch, headers=request_headers,
            auth=app_state.peer_channel_basic_auth) as response:
        result = await response.json()
    response_headers = {'User-Agent': 'ESV-Ref-Server'}
    return web.json_response(result, status=200, reason='OK', headers=response_headers)


async def get_single_channel_details(request: web.Request) -> web.Response:
    client_session: aiohttp.ClientSession = request.app['client_session']
    app_state: ApplicationState = request.app['app_state']

    channelid = request.match_info.get('channelid')

    # Todo - app_state.peer_channel_account_id change to the user's account_id based on
    #  Bearer token linkage in SQLiteDB
    url_to_fetch = f"{app_state.peer_channels_url}/api/v1/account/{app_state.peer_channel_account_id}/channel/{channelid}"
    request_headers = {'Accept': 'application/json'}
    async with client_session.get(url_to_fetch, headers=request_headers,
            auth=app_state.peer_channel_basic_auth) as response:
        result = await response.json()
    response_headers = {'User-Agent': 'ESV-Ref-Server'}
    return web.json_response(result, status=200, reason='OK', headers=response_headers)


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
# Todo - fill this in later...

# ----- NOTIFICATION & PUSH NOTIFICATION API ----- #
# Todo - fill this in later... (/api/v1/channel/{channelid}/notify)

from __future__ import annotations

import os
from datetime import datetime, timedelta
import logging
from typing import Any, Dict, Optional, TYPE_CHECKING

import aiohttp
from aiohttp import web

from .account import VerifiableKeyData, verify_key_data
from .constants import SERVER_HOST, SERVER_PORT


if TYPE_CHECKING:
    from .server import ApplicationState
    from .sqlite_db import SQLiteDatabase


logger = logging.getLogger('handlers')


async def ping(request: web.Request) -> web.Response:
    return web.Response(text="true")


async def error(request: web.Request) -> web.Response:
    raise ValueError("This is a test of raising an exception in the handler")


async def get_header(request: web.Request) -> web.Response:
    client_session: aiohttp.ClientSession = request.app['client_session']
    HEADER_SV_HOST = os.getenv('HEADER_SV_HOST')
    HEADER_SV_PORT = os.getenv('HEADER_SV_PORT')

    accept_type = request.headers.get('Accept')
    blockhash = request.match_info.get('hash')
    if not blockhash:
        return web.HTTPNotFound()

    try:
        url_to_fetch = f"http://{HEADER_SV_HOST}:{HEADER_SV_PORT}/api/v1/chain/header/{blockhash}"
        if accept_type == 'application/octet-stream':
            request_headers = {'Content-Type': 'application/octet-stream'}  # Should be 'Accept'
            async with client_session.get(url_to_fetch, headers=request_headers) as response:
                result = await response.read()
            response_headers = {'Content-Type': 'application/octet-stream', 'User-Agent': 'ESV-Ref-Server'}
            return web.Response(body=result, status=200, reason='OK', headers=response_headers)

        # else: application/json
        request_headers = {'Content-Type': 'application/json'}  # Should be 'Accept'
        async with client_session.get(url_to_fetch, headers=request_headers) as response:
            result = await response.json()
        response_headers = {'User-Agent': 'ESV-Ref-Server'}
        return web.json_response(result, status=200, reason='OK', headers=response_headers)
    except aiohttp.ClientConnectorError as e:
        logger.error(f"HeaderSV service is unavailable on http://{HEADER_SV_HOST}:{HEADER_SV_PORT}")
        return web.HTTPServiceUnavailable()


async def get_headers_by_height(request: web.Request) -> web.Response:
    client_session: aiohttp.ClientSession = request.app['client_session']
    HEADER_SV_HOST = os.getenv('HEADER_SV_HOST')
    HEADER_SV_PORT = os.getenv('HEADER_SV_PORT')

    accept_type = request.headers.get('Accept')
    params = request.rel_url.query
    height = params.get('height')
    count = params.get('count', '1')

    try:
        url_to_fetch = f"http://{HEADER_SV_HOST}:{HEADER_SV_PORT}/api/v1/chain/header/byHeight?height={height}&count={count}"
        if accept_type == 'application/octet-stream':
            request_headers = {'Accept': 'application/octet-stream'}
            async with client_session.get(url_to_fetch, headers=request_headers) as response:
                result = await response.read()
            response_headers = {'Content-Type': 'application/octet-stream', 'User-Agent': 'ESV-Ref-Server'}
            return web.Response(body=result, status=200, reason='OK', headers=response_headers)

        # else: application/json
        request_headers = {'Accept': 'application/json'}
        async with client_session.get(url_to_fetch, headers=request_headers) as response:
            result = await response.json()
        response_headers = {'User-Agent': 'ESV-Ref-Server'}
        return web.json_response(result, status=200, reason='OK', headers=response_headers)
    except aiohttp.ClientConnectorError as e:
        logger.error(f"HeaderSV service is unavailable on http://{HEADER_SV_HOST}:{HEADER_SV_PORT}")
        return web.HTTPServiceUnavailable()


async def get_chain_tips(request: web.Request) -> web.Response:
    client_session: aiohttp.ClientSession = request.app['client_session']
    HEADER_SV_HOST = os.getenv('HEADER_SV_HOST')
    HEADER_SV_PORT = os.getenv('HEADER_SV_PORT')

    url_to_fetch = f"http://{HEADER_SV_HOST}:{HEADER_SV_PORT}/api/v1/chain/tips"
    request_headers = {'Accept': 'application/json'}
    async with client_session.get(url_to_fetch, headers=request_headers) as response:
        result = await response.json()
    response_headers = {'User-Agent': 'ESV-Ref-Server'}
    # Todo - if we do not like json, we need to come up with a binary protocol for this
    return web.json_response(result, status=200, reason='OK', headers=response_headers)


async def get_account(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app['app_state']
    sqlite_db: SQLiteDatabase = app_state.sqlite_db

    auth_string = request.headers.get('Authorization', None)
    account_id: Optional[int] = None
    if auth_string is not None:
        if not auth_string.startswith("Bearer "):
            raise ValueError("Invalid API key")

        api_key = auth_string[7:]
        account_id = sqlite_db.get_account_id_for_api_key(api_key)
    else:
        if not request.body_exists:
            raise ValueError("Body required")

        # TODO This should not be json, json is garbage.
        key_data: VerifiableKeyData = await request.json()
        if not verify_key_data(key_data):
            # We do not reveal if the account exists or the key data was invalid.
            raise web.HTTPUnauthorized()

        public_key_bytes = bytes.fromhex(key_data["public_key_hex"])
        account_id = sqlite_db.get_account_id_for_public_key_bytes(public_key_bytes)

    if account_id is None:
        # We do not reveal if the account does not exist or the key data was invalid.
        raise web.HTTPUnauthorized()

    m_public_key_bytes, m_api_key = sqlite_db.get_account_metadata_for_account_id(account_id)
    # This should never happen but we error if it does.
    assert m_public_key_bytes != b""
    data = {
        "public_key_hex": m_public_key_bytes.hex(),
        "api_key": m_api_key,
    }
    return web.json_response(data)


async def get_endpoints_data(request: web.Request) -> web.Response:
    utc_now_datetime = datetime.utcnow()
    utc_expiry_datetime = utc_now_datetime + timedelta(days=1)

    data: Dict[str, Any] = {
        "apiType": "bsvapi.endpoints",
        "apiVersion": 1,
        "baseUrl": f"http://{SERVER_HOST}:{SERVER_PORT}",
        "timestamp": utc_now_datetime.isoformat() +"Z",
        "expiryTime": utc_expiry_datetime.isoformat() +"Z",
        "endpoints": [
            {
                "apiType": "bsvapi.account",
                "apiVersion": 1,
                "baseURL": "/api/v1/account",
            },
            {
                "apiType": "bsvapi.header",
                "apiVersion": 1,
                "baseURL": "/api/v1/headers",
            },
        ]
    }
    return web.json_response(data=data)

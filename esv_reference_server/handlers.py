from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timedelta
import logging
from typing import Any, Dict, Optional, TYPE_CHECKING

import aiohttp
from aiohttp import web

from .account import VerifiableKeyData, verify_key_data
from .constants import SERVER_HOST, SERVER_PORT
from .types import PeerChannelAccountRow

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
    app_state: ApplicationState = request.app['app_state']

    accept_type = request.headers.get('Accept')
    blockhash = request.match_info.get('hash')
    if not blockhash:
        return web.HTTPNotFound()

    try:
        url_to_fetch = f"{app_state.header_sv_url}/api/v1/chain/header/{blockhash}"
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
        logger.error(f"HeaderSV service is unavailable on {app_state.header_sv_url}")
        return web.HTTPServiceUnavailable()


async def get_headers_by_height(request: web.Request) -> web.Response:
    client_session: aiohttp.ClientSession = request.app['client_session']
    app_state: ApplicationState = request.app['app_state']

    accept_type = request.headers.get('Accept')
    params = request.rel_url.query
    height = params.get('height')
    count = params.get('count', '1')

    try:
        url_to_fetch = f"{app_state.header_sv_url}/api/v1/chain/header/byHeight?height={height}&count={count}"
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
        logger.error(f"HeaderSV service is unavailable on {app_state.header_sv_url}")
        return web.HTTPServiceUnavailable()


async def get_chain_tips(request: web.Request) -> web.Response:
    client_session: aiohttp.ClientSession = request.app['client_session']
    app_state: ApplicationState = request.app['app_state']

    url_to_fetch = f"{app_state.header_sv_url}/api/v1/chain/tips"
    request_headers = {'Accept': 'application/json'}
    async with client_session.get(url_to_fetch, headers=request_headers) as response:
        result = await response.json()
    response_headers = {'User-Agent': 'ESV-Ref-Server'}
    # Todo - if we do not like json, we need to come up with a binary protocol for this
    return web.json_response(result, status=200, reason='OK', headers=response_headers)


# Todo - replace this with the real 'create_account' handler when Roger had finished it
#  add the _create_peer_channel_account() functionality to Roger's implementation
async def dummy_create_account(request: web.Request) -> web.Response:
    """This is a mock of the handler that will create the account on successfully opening a payment
    channel"""
    app_state: ApplicationState = request.app['app_state']
    client_session: aiohttp.ClientSession = request.app['client_session']
    sqlite_db: SQLiteDatabase = app_state.sqlite_db

    # Todo - replace this part with Roger's actual implementation when ready
    # ASSUME THAT PAYMENT CHANNEL CREATION WAS SUCCESSFUL AND A NEW ACCOUNT IS NOW CREATED WITH:
    # Also assume the Authentication method was 'BSVKeyData'
    dummy_account_id = 12345
    dummy_pubkey_hex = '0000000000000000000000000000000000000000000000000000000000000000'
    dummy_api_key = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
    sql = (f"""
        INSERT INTO accounts VALUES({dummy_account_id}, X'{dummy_pubkey_hex}', X'{dummy_api_key}'
        )""")
    sqlite_db.execute(sql)

    # Todo - extend Roger's implementation with this (Peer Channel account creation):
    request_headers = {
        'Accept': 'application/json',
        'Authorization': f'Bearer: {app_state.peer_channel_master_account_creation_token}'}
    url_to_fetch = f"http://127.0.0.1:5000/api/v1/account"

    request_body = {
        'account_name': dummy_pubkey_hex,
        'username': dummy_pubkey_hex,
        'password': dummy_api_key,
    }

    async with client_session.post(url_to_fetch, json=request_body,
            headers=request_headers) as response:
        response.raise_for_status()
        result = await response.json()

    # Todo - do not log this or return this to client (it's a hidden implementation detail)
    logger.debug(f"Created account: {result}")

    # link the main, global payment channel account_id to the peer channel account_id
    # and basic auth credentials
    account_row = PeerChannelAccountRow(
        peer_channel_account_id=result['account_id'],
        peer_channel_account_name=dummy_pubkey_hex,
        peer_channel_username=dummy_pubkey_hex,
        peer_channel_password=dummy_api_key,
        account_id=dummy_account_id)
    sqlite_db.insert_peer_channel_account(account_row)

    # Todo - As per https://docs.google.com/document/d/1l_3ElDrkFa44A46yHqYWk5Xbmq7262aUUgVl-GICwss/edit
    #  if the Authentication method was 'BSVKeyData' -> include the Bearer Token API key
    #  in the response
    return web.HTTPOk()


async def get_account(request: web.Request) -> web.Response:
    """Two alternative forms of authentication. Either Bearer Token auth required"""
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

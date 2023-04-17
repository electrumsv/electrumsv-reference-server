"""
Copyright(c) 2021 Bitcoin Association.
Distributed under the Open BSV software license, see the accompanying file LICENSE
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta
import logging
from typing import Any, Dict, Optional, TYPE_CHECKING

from aiohttp import web

from .keys import VerifiableKeyDataDict, verify_key_data
from .constants import AccountFlag, EXTERNAL_SERVER_HOST, EXTERNAL_SERVER_PORT
from .sqlite_db import create_account, get_account_id_for_api_key, \
    get_account_id_for_public_key_bytes, get_account_metadata_for_account_id


if TYPE_CHECKING:
    from .keys import ServerKeys
    from .application_state import ApplicationState


logger = logging.getLogger('handlers')


async def ping(request: web.Request) -> web.Response:
    return web.Response(text="ElectrumSV Reference Server")


async def get_account(request: web.Request) -> web.Response:
    """Two alternative forms of authentication. Either Bearer Token auth required"""
    app_state: ApplicationState = request.app['app_state']

    account_id: Optional[int] = None
    auth_string = request.headers.get('Authorization', None)
    if auth_string is not None:
        if not auth_string.startswith("Bearer "):
            raise web.HTTPBadRequest(reason="Invalid API key")

        api_key = auth_string[7:]
        account_id, account_flags = get_account_id_for_api_key(app_state.database_context, api_key)
    else:
        if not request.body_exists:
            raise web.HTTPBadRequest(reason="Body required")

        key_data: VerifiableKeyDataDict = await request.json()
        try:
            if not verify_key_data(key_data):
                # We do not reveal if the account exists or the key data was invalid.
                raise web.HTTPUnauthorized()
        except (KeyError, TypeError, ValueError):
            raise web.HTTPBadRequest(reason="Invalid key data type")

        public_key_bytes = bytes.fromhex(key_data["public_key_hex"])
        account_id, account_flags = get_account_id_for_public_key_bytes(app_state.database_context,
            public_key_bytes)
    # We do not reveal if the account does not exist/is disabled or the key data was invalid.
    if account_id is None or account_flags & AccountFlag.DISABLED_MASK:
        raise web.HTTPUnauthorized

    metadata = get_account_metadata_for_account_id(app_state.database_context, account_id)
    # This should never happen but we error if it does.
    assert metadata.public_key_bytes != b""
    data = {
        "public_key_hex": metadata.public_key_bytes.hex(),
        "api_key": metadata.api_key,
    }
    return web.json_response(data)


async def post_account_registration(request: web.Request) -> web.Response:
    """
    Automated account sign-up flow via the API. These accounts are considered anonymous accounts
    and may be restricted in the usage they can make among the wider grouping of anonymous accounts.

    There is no asynchronicity within this handler so it should be safe from any race conditions
    by any client submitting multiple requests to it.

    Error responses:
        400 / bad request   No body with client key data or client key data badly formed.
        401 / unauthorized  The client key data failed validation.
    """
    # TODO(nocheckin) Update the swagger for the errors, input and return value.
    if not request.body_exists:
        raise web.HTTPBadRequest()

    app_state: ApplicationState = request.app['app_state']

    account_id: int | None = None
    account_public_key_bytes: bytes | None = None

    key_data: VerifiableKeyDataDict = await request.json()
    # TODO(nocheckin) This should expect a dated signed message.
    try:
        if not verify_key_data(key_data):
            # We do not reveal if the account exists or the key data was invalid.
            raise web.HTTPUnauthorized()
    except (KeyError, TypeError, ValueError):
        raise web.HTTPBadRequest(reason="Invalid key data type")

    account_public_key_bytes = bytes.fromhex(key_data["public_key_hex"])
    account_id, account_flags = get_account_id_for_public_key_bytes(app_state.database_context,
        account_public_key_bytes)
    if account_flags & AccountFlag.DISABLED_MASK:
        raise web.HTTPUnauthorized()

    if account_id is None:
        account_id, api_key = await app_state.database_context.run_in_thread_async(
            create_account, account_public_key_bytes)
    else:
        metadata = get_account_metadata_for_account_id(app_state.database_context, account_id)
        api_key = metadata.api_key

    return web.json_response({
        "public_key_hex": key_data["public_key_hex"],
        "api_key": api_key,
    })


async def get_endpoints_data(request: web.Request) -> web.Response:
    utc_now_datetime = datetime.utcnow()
    utc_expiry_datetime = utc_now_datetime + timedelta(days=1)

    data: Dict[str, Any] = {
        "apiType": "bsvapi.endpoint",
        "apiVersion": 1,
        "baseUrl": f"http://{EXTERNAL_SERVER_HOST}:{EXTERNAL_SERVER_PORT}",
        "timestamp": utc_now_datetime.isoformat() +"Z",
        "expiryTime": utc_expiry_datetime.isoformat() +"Z",
        "endpoints": [
            {
                "apiType": "bsvapi.account",
                "apiVersion": 1,
                "baseUrl": "/api/v1/account",
            },
            {
                "apiType": "bsvapi.channel",
                "apiVersion": 1,
                "baseUrl": "/api/v1/channel"
            },
            {
                "apiType": "bsvapi.websocket",
                "apiVersion": 1,
                "baseUrl": "/api/v1/web-socket"
            }
        ]
    }
    if os.environ.get('EXPOSE_HEADER_SV_APIS'):
        data['endpoints'].extend([
            {
                "apiType": "bsvapi.headers",
                "apiVersion": 1,
                "baseUrl": "/api/v1/headers",
            },
            {
                "apiType": "bsvapi.network",
                "apiVersion": 1,
                "baseUrl": "/api/v1/network",
            },
        ])
    if os.environ.get('EXPOSE_INDEXER_APIS'):
        data['endpoints'].extend([
            {
                "apiType": "bsvapi.transaction",
                "apiVersion": 1,
                "baseURL": "/api/v1/transaction",
            },
            {
                "apiType": "bsvapi.merkle-proof",
                "apiVersion": 1,
                "baseURL": "/api/v1/merkle-proof",
            },
            {
                "apiType": "bsvapi.output-spend",
                "apiVersion": 1,
                "baseURL": "/api/v1/output-spend",
            },
            {
                "apiType": "bsvapi.restoration",
                "apiVersion": 1,
                "baseURL": "/api/v1/restoration",
                "pricing": {
                    "data": {
                        "satoshis": 4524,
                        "bytes": 10000000,
                    }
                }
            }
        ])
    return web.json_response(data=data)


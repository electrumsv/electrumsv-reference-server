"""
Copyright(c) 2021 Bitcoin Association.
Distributed under the Open BSV software license, see the accompanying file LICENSE
"""

from __future__ import annotations

from datetime import datetime, timedelta
import logging
import time
from typing import Any, Dict, Optional, TYPE_CHECKING

import aiohttp
from aiohttp import web
from bitcoinx import P2MultiSig_Output, Signature

from .keys import generate_payment_public_key, \
    VerifiableKeyData, verify_key_data
from .constants import AccountFlags, ChannelState, SERVER_HOST, SERVER_PORT
from . import networks
from .networks import mapi_broadcast_transaction
from .payment_channels import BrokenChannelError, InvalidTransactionError, \
    process_contract_update_async, process_contract_close_async, process_funding_script, \
    process_funding_transaction_async, process_refund_contract_transaction
from . import sqlite_db as database


if TYPE_CHECKING:
    from .keys import ServerKeys
    from .server import ApplicationState
    from .sqlite_db import SQLiteDatabase


logger = logging.getLogger('handlers')


async def ping(request: web.Request) -> web.Response:
    return web.Response(text="ElectrumSV Reference Server")


async def get_account(request: web.Request) -> web.Response:
    """Two alternative forms of authentication. Either Bearer Token auth required"""
    app_state: ApplicationState = request.app['app_state']
    db: SQLiteDatabase = app_state.sqlite_db

    account_id: Optional[int] = None
    auth_string = request.headers.get('Authorization', None)
    if auth_string is not None:
        if not auth_string.startswith("Bearer "):
            raise web.HTTPBadRequest(reason="Invalid API key")

        api_key = auth_string[7:]
        account_id, account_flags = db.get_account_id_for_api_key(api_key)
    else:
        if not request.body_exists:
            raise web.HTTPBadRequest(reason="Body required")

        key_data: VerifiableKeyData = await request.json()
        if not verify_key_data(key_data):
            # We do not reveal if the account exists or the key data was invalid.
            raise web.HTTPUnauthorized()

        public_key_bytes = bytes.fromhex(key_data["public_key_hex"])
        account_id, account_flags = db.get_account_id_for_public_key_bytes(public_key_bytes)
    # We do not reveal if the account does not exist/is disabled or the key data was invalid.
    if account_id is None or account_flags & AccountFlags.DISABLED_MASK:
        raise web.HTTPUnauthorized

    metadata = db.get_account_metadata_for_account_id(account_id)
    # This should never happen but we error if it does.
    assert metadata.public_key_bytes != b""
    data = {
        "public_key_hex": metadata.public_key_bytes.hex(),
        "api_key": metadata.api_key,
    }
    return web.json_response(data)


async def post_account_key(request: web.Request) -> web.Response:
    """
    Start the payment channel funding process by generating a payment key for the given client.
    If the client does not have an account this is part of the process of creating their account.
    If the client does have an account they must not have an active payment channel.

    There is no asynchronicity within this handler so it should be safe from any race conditions
    by any client submitting multiple requests to it.

    Error responses:
        400 / bad request   Invalid API key type or no body with client key data.
        401 / unauthorized  An API key was provided and it was invalid or the client key data was
                            not valid.
        409 / conflict      There is an existing active payment channel.
    """
    app_state: ApplicationState = request.app['app_state']
    db: SQLiteDatabase = app_state.sqlite_db
    server_keys: ServerKeys = app_state.server_keys

    account_id: Optional[int] = None
    account_public_key_bytes: Optional[bytes] = None
    payment_key_index: int = 0
    payment_key_bytes: Optional[bytes] = None
    auth_string = request.headers.get('Authorization', None)
    api_key: str
    if auth_string is not None:
        if not auth_string.startswith("Bearer "):
            raise web.HTTPBadRequest

        api_key = auth_string[7:]
        account_id, _account_flags = db.get_account_id_for_api_key(api_key)
        if account_id is None:
            # We do not reveal if the account exists or the key data was invalid.
            raise web.HTTPUnauthorized

        metadata = db.get_account_metadata_for_account_id(account_id)
        if metadata.active_channel_id is not None:
            raise web.HTTPConflict

        payment_key_index = metadata.last_payment_key_index

        if account_public_key_bytes is None:
            assert len(metadata.public_key_bytes)
            account_public_key_bytes = metadata.public_key_bytes
    else:
        if not request.body_exists:
            raise web.HTTPBadRequest

        key_data: VerifiableKeyData = await request.json()
        if not verify_key_data(key_data):
            # We do not reveal if the account exists or the key data was invalid.
            raise web.HTTPUnauthorized

        account_public_key_bytes = bytes.fromhex(key_data["public_key_hex"])
        account_id, account_flags = db.get_account_id_for_public_key_bytes(account_public_key_bytes)
        if account_flags & AccountFlags.DISABLED_MASK:
            raise web.HTTPUnauthorized

        if account_id is None:
            account_id, api_key = db.create_account(account_public_key_bytes)
            payment_key_index = 1
        else:
            metadata = db.get_account_metadata_for_account_id(account_id)
            if metadata.flags & AccountFlags.MID_CREATION:
                # This is a user with an account in the process of being created, and the required
                # action is that they fund it. If they request a fresh payment key they are
                # resetting the funding process.
                assert metadata.active_channel_id is not None
                db.delete_account_payment_channel(metadata.active_channel_id)
            else:
                # This should be an active user who is opening a new payment channel and does not
                # have an active one.
                if metadata.active_channel_id is not None:
                    raise web.HTTPConflict
            payment_key_index = metadata.last_payment_key_index + 1
            api_key = metadata.api_key

    # Ensure all paths that reach here have set an index to use.
    assert payment_key_index > 0
    payment_key_bytes = generate_payment_public_key(server_keys.identity_public_key,
        account_public_key_bytes, payment_key_index).to_bytes()
    db.create_account_payment_channel(account_id, payment_key_index, payment_key_bytes)

    mpwriter = aiohttp.MultipartWriter()
    part = mpwriter.append(payment_key_bytes)
    part.set_content_disposition('inline', name="key")

    part = mpwriter.append(api_key)
    part.set_content_disposition('inline', name="api-key")

    response = web.Response()
    response.body = mpwriter
    return response


async def post_account_channel(request: web.Request) -> web.Response:
    """
    Accept the initial version of the contract from the client. The initial version of the contract
    acts as insurance for the client in the form of being a complete refund.
    """
    app_state: ApplicationState = request.app['app_state']
    db: SQLiteDatabase = app_state.sqlite_db

    auth_string = request.headers.get('Authorization', None)
    if auth_string is None or not auth_string.startswith("Bearer "):
        raise web.HTTPBadRequest(reason="No 'Bearer' authentication")

    api_key = auth_string[7:]
    account_id, _account_flags = db.get_account_id_for_api_key(api_key)
    if account_id is None:
        # We do not reveal if the account exists or the api key was invalid.
        raise web.HTTPUnauthorized

    channel_row = db.get_active_channel_for_account_id(account_id)
    if channel_row is None or channel_row.channel_state != ChannelState.PAYMENT_KEY_DISPENSED:
        raise web.HTTPBadRequest(reason="Channel invalid")

    # Request processing.
    funding_value_text = request.query.get("funding_value")
    if funding_value_text is None:
        raise web.HTTPBadRequest(reason="Missing 'funding_value' parameter")
    funding_value = int(funding_value_text)

    funding_p2ms: Optional[P2MultiSig_Output] = None
    funding_script_bytes = b""
    contract_transaction_bytes = b""
    async for part_reader in await request.multipart():
        if part_reader.name == "script":
            funding_script_bytes = await part_reader.read(decode=True)
            funding_p2ms = process_funding_script(funding_script_bytes,
                channel_row.payment_key_bytes)
            if funding_p2ms is None:
                raise web.HTTPBadRequest(reason="Invalid 'script' multipart payload")
        elif part_reader.name == "transaction":
            contract_transaction_bytes = await part_reader.read(decode=True)
        else:
            part_name = part_reader.name or "?"
            raise web.HTTPBadRequest(reason=f"Invalid '{part_name}' multipart")
    if not funding_script_bytes:
        raise web.HTTPBadRequest(reason="Missing the 'script' multipart payload")
    if not contract_transaction_bytes:
        raise web.HTTPBadRequest(reason="Missing the 'transaction' multipart payload")
    assert funding_p2ms is not None

    delivery_time = int(time.time())
    account_metadata = db.get_account_metadata_for_account_id(account_id)
    if account_metadata is None:
        raise web.HTTPUnauthorized
    try:
        client_payment_key_bytes, funding_transaction_hash, refund_signature_bytes = \
            process_refund_contract_transaction(
                contract_transaction_bytes, delivery_time, funding_value, funding_p2ms,
                app_state.server_keys, account_metadata, channel_row)
    except InvalidTransactionError as exc:
        raise web.HTTPBadRequest(reason=exc.args[0])

    db.set_payment_channel_initial_contract_transaction(channel_row.channel_id,
        funding_value, funding_transaction_hash, funding_value, refund_signature_bytes,
        contract_transaction_bytes, client_payment_key_bytes)
    return web.Response(body=refund_signature_bytes, content_type="application/octet-stream")


async def put_account_channel_update(request: web.Request) -> web.Response:
    """
    Accept a contract amendment from the client. This is a decreased refund to themselves and
    an increased payment to us.
    """
    app_state: ApplicationState = request.app['app_state']
    db: SQLiteDatabase = app_state.sqlite_db

    auth_string = request.headers.get('Authorization', None)
    if auth_string is None or not auth_string.startswith("Bearer "):
        raise web.HTTPBadRequest(reason="No 'Bearer' authentication")

    api_key = auth_string[7:]
    account_id, account_flags = db.get_account_id_for_api_key(api_key)
    if account_id is None:
        # We do not reveal if the account exists or the api key was invalid.
        raise web.HTTPUnauthorized

    channel_row = db.get_active_channel_for_account_id(account_id)
    if channel_row is None or channel_row.channel_state != ChannelState.CONTRACT_OPEN:
        raise web.HTTPBadRequest(reason="Channel invalid")

    # Request processing.
    refund_value_text = request.query.get("refund_value")
    if refund_value_text is None:
        raise web.HTTPBadRequest(reason="Missing 'refund_value' parameter")
    refund_value = int(refund_value_text)

    refund_signature_bytes = b""
    async for part_reader in await request.multipart():
        if part_reader.name == "signature":
            refund_signature_bytes = await part_reader.read(decode=True)
            if Signature.analyze_encoding(refund_signature_bytes) == 0:
                raise web.HTTPBadRequest(reason="Invalid signature")
        else:
            part_name = part_reader.name or "?"
            raise web.HTTPBadRequest(reason=f"Invalid '{part_name}' multipart")
    if not refund_signature_bytes:
        raise web.HTTPBadRequest(reason="Missing the 'signature' multipart payload")

    try:
        new_refund_sequence = await process_contract_update_async(refund_signature_bytes,
            refund_value, channel_row)
    except BrokenChannelError as exc:
        # These errors are ones that can only be made by someone who is intentionally
        # messing with the server. They have to have done the signature correctly already
        # in establishing the initial full refund contract.
        db.deactivate_account(account_id, AccountFlags.DISABLED_FLAGGED)
        raise web.HTTPNotAcceptable(reason=exc.args[0])

    try:
        db.update_payment_channel_contract(channel_row.channel_id, refund_value,
            refund_signature_bytes, new_refund_sequence)
    except database.DatabaseStateModifiedError:
        raise web.HTTPBadRequest(reason="Channel state inconsistency")

    # If this is the first time the client has given us a payment through the payment channel
    # then we change their account from one that is mid creation to one that is registered.
    if account_flags & AccountFlags.MID_CREATION:
        try:
            db.set_account_registered(account_id)
        except database.DatabaseStateModifiedError:
            raise web.HTTPBadRequest(reason="Account inconsistency")

    return web.Response()


async def post_account_funding(request: web.Request) -> web.Response:
    """
    Receive the funding transaction from the client. It is expected that the client will have
    broadcast the transaction before they give it to us, although this is not a requirement.
    """
    app_state: ApplicationState = request.app['app_state']
    db: SQLiteDatabase = app_state.sqlite_db

    auth_string = request.headers.get('Authorization', None)
    if auth_string is None or not auth_string.startswith("Bearer "):
        raise web.HTTPBadRequest(reason="No 'Bearer' authentication")

    api_key = auth_string[7:]
    account_id, _account_flags = db.get_account_id_for_api_key(api_key)
    if account_id is None:
        # We do not reveal if the account exists or the api key was invalid.
        raise web.HTTPUnauthorized

    channel_row = db.get_active_channel_for_account_id(account_id)
    if channel_row is None or channel_row.channel_state != ChannelState.REFUND_ESTABLISHED:
        raise web.HTTPBadRequest(reason="Channel invalid")

    funding_transaction_bytes = b""
    async for part_reader in await request.multipart():
        if part_reader.name == "transaction":
            funding_transaction_bytes = await part_reader.read(decode=True)
        else:
            part_name = part_reader.name or "?"
            raise web.HTTPBadRequest(reason=f"Invalid '{part_name}' multipart")
    if not funding_transaction_bytes:
        raise web.HTTPBadRequest(reason="Missing the 'transaction' multipart payload")

    try:
        funding_output_script_bytes = await process_funding_transaction_async(
            funding_transaction_bytes, channel_row)
    except BrokenChannelError as exc:
        db.set_payment_channel_closed(channel_row.channel_id,
            ChannelState.CLOSED_INVALID_FUNDING_TRANSACTION)
        raise web.HTTPNotAcceptable(reason=exc.args[0])

    try:
        await mapi_broadcast_transaction(app_state.network, funding_transaction_bytes)
    except (aiohttp.ClientError, networks.NetworkError) as exc:
        db.set_payment_channel_closed(channel_row.channel_id,
            ChannelState.CLOSED_BROADCASTING_FUNDING_TRANSACTION)
        raise web.HTTPNotAcceptable(reason=exc.args[0])

    # TODO(utxo-spends) We should register for the spend of the funding output and react to it.

    try:
        db.set_payment_channel_funding_transaction(channel_row.channel_id,
            funding_transaction_bytes, funding_output_script_bytes)
    except database.DatabaseStateModifiedError:
        raise web.HTTPBadRequest(reason="Channel state inconsistency")

    return web.Response()


async def delete_account_channel(request: web.Request) -> web.Response:
    """
    Close the payment channel for the client.
    """
    app_state: ApplicationState = request.app['app_state']
    db: SQLiteDatabase = app_state.sqlite_db

    auth_string = request.headers.get('Authorization', None)
    if auth_string is None or not auth_string.startswith("Bearer "):
        raise web.HTTPBadRequest(reason="No 'Bearer' authentication")

    api_key = auth_string[7:]
    account_id, _account_flags = db.get_account_id_for_api_key(api_key)
    if account_id is None:
        # We do not reveal if the account exists or the api key was invalid.
        raise web.HTTPUnauthorized

    channel_row = db.get_active_channel_for_account_id(account_id)
    if channel_row is None or channel_row.channel_state != ChannelState.REFUND_ESTABLISHED:
        raise web.HTTPBadRequest(reason="Channel invalid")

    refund_value_str = request.query.get("refund_value")
    if refund_value_str is None:
        raise web.HTTPBadRequest(reason="Missing 'refund_value' parameter")
    refund_value = int(refund_value_str)

    refund_signature_bytes = b""
    async for part_reader in await request.multipart():
        if part_reader.name == "signature":
            refund_signature_bytes = await part_reader.read(decode=True)
            if Signature.analyze_encoding(refund_signature_bytes) == 0:
                raise web.HTTPBadRequest(reason="Invalid signature")
        else:
            part_name = part_reader.name or "?"
            raise web.HTTPBadRequest(reason=f"Invalid '{part_name}' multipart")
    if not refund_signature_bytes:
        raise web.HTTPBadRequest(reason="Missing the 'signature' multipart payload")

    account_metadata = db.get_account_metadata_for_account_id(account_id)
    if account_metadata is None:
        raise web.HTTPUnauthorized

    contract_transaction_bytes = await process_contract_close_async(refund_signature_bytes,
        refund_value, app_state.server_keys, account_metadata, channel_row)
    try:
        await mapi_broadcast_transaction(app_state.network, contract_transaction_bytes)
    except (aiohttp.ClientError, networks.NetworkError) as exc:
        # TODO(critical-to-fix): What do we do when claiming the contact/broadcasting errors?
        #   - It could be because the fee was not high enough.
        #   - It could be because the transaction structure is invalid and we checked it wrong.
        #   - It could be because ???
        raise web.HTTPNotAcceptable(reason=exc.args[0])

    return web.Response()


async def get_endpoints_data(request: web.Request) -> web.Response:
    utc_now_datetime = datetime.utcnow()
    utc_expiry_datetime = utc_now_datetime + timedelta(days=1)

    data: Dict[str, Any] = {
        "apiType": "bsvapi.endpoint",
        "apiVersion": 1,
        "baseUrl": f"http://{SERVER_HOST}:{SERVER_PORT}",
        "timestamp": utc_now_datetime.isoformat() +"Z",
        "expiryTime": utc_expiry_datetime.isoformat() +"Z",
        "endpoints": [
            {
                "apiType": "bsvapi.account",
                "apiVersion": 1,
                "baseUrl": "/api/v1/account",
            },
            {
                "apiType": "bsvapi.header",
                "apiVersion": 1,
                "baseUrl": "/api/v1/headers",
            },
        ]
    }
    return web.json_response(data=data)

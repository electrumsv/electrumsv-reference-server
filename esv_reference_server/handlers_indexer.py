# Copyright(c) 2021-2022 Bitcoin Association.
# Distributed under the Open BSV software license, see the accompanying file LICENSE
#
# The ElectrumSV project supports open APIs. We do not however provide a production blockchain
# indexer, as that is outside the scope of our work. This file is intended to allow any user
# who implements their own indexer, to integrate it into the reference server instance they
# may also run. Or for users who are doing development to do so against the simple indexer
# we provide for usage on regtest.

from __future__ import annotations
import http
import json
import logging
from typing import cast, Optional, TYPE_CHECKING

import aiohttp
from aiohttp import web
from bitcoinx import hash_to_hex_str, hex_str_to_hash

from .constants import IndexerPushdataRegistrationFlag
from .sqlite_db import create_indexer_filtering_registrations_pushdatas, \
    DatabaseStateModifiedError, delete_indexer_filtering_registrations_pushdatas, \
    read_indexer_filtering_registrations_pushdatas, \
    update_indexer_filtering_registrations_pushdatas_flags
from .types import Outpoint, outpoint_struct

if TYPE_CHECKING:
    from .server import ApplicationState


logger = logging.getLogger("handlers-indexer")


def _check_indexer_connected(app_state: ApplicationState) -> None:
    # We use the open web socket to the indexer as an indication that it is active/accessible.
    if not app_state.indexer_is_connected:
        raise web.HTTPServiceUnavailable(reason="This functionality is temporarily unavailable")


async def mirrored_indexer_call_async(request: web.Request, *,
        body: Optional[bytes]=None, query_params: Optional[dict[str, str]]=None) -> web.Response:
    """
    The indexer functionality must be provided by the party who is running the reference server
    and exposed via the `INDEXER_URL` environment variable. This function mirrors calls made
    on reference server endpoints onto the given indexer instance.
    """
    client_session: aiohttp.ClientSession = request.app['client_session']
    app_state: ApplicationState = request.app['app_state']

    _check_indexer_connected(app_state)

    method_name = request.method.lower()
    if body is None and method_name == "post":
        body = await request.content.read()
        if not body:
            raise web.HTTPBadRequest(reason="no body provided")

    accept_type = request.headers.get("Accept", "application/octet-stream")
    content_type = request.headers.get("Content-Type", "application/octet-stream")

    indexer_path = request.path
    request_headers = {
        "Accept": accept_type,
        "Content-Type": content_type
    }
    url_to_fetch = f"{app_state.indexer_url}{indexer_path}"
    session_method = getattr(client_session, method_name)
    async with session_method(url_to_fetch, params=query_params, headers=request_headers,
            data=body) as response:
        # Propagate any indexer error to the caller.
        # TODO This is not quite correct. There are dozens of arcane response status codes between
        #     the first error `BAD_REQUEST` and the last real success `ACCEPTED`.
        if not response.ok:
            logger.debug("Mirrored response failed, url=%s, status=%d", url_to_fetch,
                response.status)
            return web.Response(reason=response.reason, status=response.status)

        body_bytes = await response.read()
        if accept_type == "application/octet-stream":
            return web.Response(body=body_bytes)
        else:
            return web.json_response(body=body_bytes)


async def indexer_post_restoration_search(request: web.Request) -> web.Response:
    """
    Optional endpoint if running an indexer.

    Give the client access to any restoration index held by any running indexer.
    """
    # TODO(1.4.0) This should be monetised with a free quota.
    return await mirrored_indexer_call_async(request)


async def indexer_get_transaction_filter(request: web.Request) -> web.Response:
    # TODO(1.4.0) This should be monetised with a free quota.
    accept_type = request.headers.get('Accept', "application/json")
    if accept_type not in { "application/json", "application/octet-stream" }:
        raise web.HTTPBadRequest(reason="unknown request body content type")

    app_state: ApplicationState = request.app['app_state']

    account_id = app_state.temporary_account_id
    assert account_id is not None

    # Note that this cannot be relied on to provide the client application's state, as it will
    # contain entries in the process of being deleted for instance.
    pushdata_hashes = read_indexer_filtering_registrations_pushdatas(app_state.database_context,
        account_id, IndexerPushdataRegistrationFlag.FINALISED,
        IndexerPushdataRegistrationFlag.FINALISED)

    accept_type = request.headers.get('Accept', 'application/json')
    if accept_type == 'application/octet-stream':
        result_bytes = b"".join(pushdata_hashes)
        return web.Response(body=result_bytes)
    elif accept_type == 'application/json':
        json_list: list[str] = [
            hash_to_hex_str(pushdata_hash) for pushdata_hash in pushdata_hashes ]
        return web.json_response(data=json.dumps(json_list))
    else:
        raise web.HTTPBadRequest(reason="unknown request body content type")


async def indexer_post_transaction_filter(request: web.Request) -> web.Response:
    """
    Optional endpoint if running an indexer.

    Used by the client to register pushdata hashes for new/updated transactions so that they can
    know about new occurrences of their pushdatas. This should be safe for consecutive calls
    even for the same pushdata, as the database unique constraint should raise an integrity
    error if there is an ongoing registration.
    """
    # TODO(1.4.0) This should be monetised with a free quota.
    accept_type = request.headers.get('Accept', "application/json")
    if accept_type not in { "application/json", "application/octet-stream" }:
        raise web.HTTPBadRequest(reason="unknown request body content type")

    # TODO(1.4.0) This should be monetised with a free quota.
    app_state: ApplicationState = request.app['app_state']

    # This is also done by the mirrored call, but we want to avoid storing local state before
    # the indexer call in case we have to back it out.
    _check_indexer_connected(app_state)

    account_id = app_state.temporary_account_id
    assert account_id is not None

    body = await request.content.read()
    if not body:
        raise web.HTTPBadRequest(reason="no body")

    pushdata_hashes: set[bytes] = set()
    content_type = request.headers.get("Content-Type")
    body_bytes: Optional[bytes] = None
    if content_type == 'application/json':
        # Convert the incoming JSON representation to the internal binary representation.
        client_outpoints_json = json.loads(body.decode('utf-8'))
        if not isinstance(client_outpoints_json, list):
            raise web.HTTPBadRequest(reason="payload is not a list")
        for pushdata_hash_hex in client_outpoints_json:
            if not isinstance(pushdata_hash_hex, str):
                raise web.HTTPBadRequest(reason="one or more payload entries are incorrect")
            try:
                pushdata_hash = bytes.fromhex(pushdata_hash_hex)
            except (ValueError, TypeError):
                raise web.HTTPBadRequest(reason="one or more payload entries are incorrect")
            pushdata_hashes.add(pushdata_hash)
    elif content_type == 'application/octet-stream':
        if len(body) % 32 != 0:
            raise web.HTTPBadRequest(reason="binary request body malformed")

        for pushdata_index in range(len(body) // 32):
            pushdata_hashes.add(body[pushdata_index:pushdata_index+32])
        body_bytes = body
    else:
        raise web.HTTPBadRequest(reason="unknown request body content type")

    if not len(pushdata_hashes):
        raise web.HTTPBadRequest(reason="no pushdata hashes provided")

    # It is required that the client knows what it is doing and this is enforced by disallowing
    # any registration if any of the given pushdatas are already registered.
    if not await app_state.database_context.run_in_thread_async(
            create_indexer_filtering_registrations_pushdatas, account_id, list(pushdata_hashes)):
        raise web.HTTPBadRequest(reason="some pushdata hashes already registered")

    # Pass on the registrations to the indexer. The indexer just supports binary as it is
    # not exposed publically, so we reserialise the hashes if necessary.
    if body_bytes is None:
        body_bytes = b"".join(pushdata_hashes)

    response: Optional[web.Response] = None
    try:
        response = await mirrored_indexer_call_async(request, body=body_bytes)
    finally:
        # We only consider registrations valid if we received the only successful kind of response.
        if response is not None and response.status == http.HTTPStatus.OK:
            await app_state.database_context.run_in_thread_async(
                update_indexer_filtering_registrations_pushdatas_flags, account_id,
                    list(pushdata_hashes),
                    update_flags=IndexerPushdataRegistrationFlag.FINALISED)
        else:
            await app_state.database_context.run_in_thread_async(
                delete_indexer_filtering_registrations_pushdatas, account_id,
                list(pushdata_hashes))
    assert response is not None
    return response


async def indexer_post_transaction_filter_delete(request: web.Request) -> web.Response:
    """
    Optional endpoint if running an indexer.

    Used by the client to unregister pushdata hashes they are monitoring.
    """
    # TODO(1.4.0) This should be monetised with a free quota.
    accept_type = request.headers.get('Accept', "application/json")
    if accept_type not in { "application/json", "application/octet-stream" }:
        raise web.HTTPBadRequest(reason="unknown request body content type")

    app_state: ApplicationState = request.app['app_state']

    # This is also done by the mirrored call, but we want to avoid storing local state before
    # the indexer call in case we have to back it out.
    _check_indexer_connected(app_state)

    account_id = app_state.temporary_account_id
    assert account_id is not None

    body = await request.content.read()
    if not body:
        raise web.HTTPBadRequest(reason="no body")

    pushdata_hashes: set[bytes] = set()
    content_type = request.headers.get("Content-Type")
    body_bytes: Optional[bytes] = None
    if content_type == 'application/json':
        # Convert the incoming JSON representation to the internal binary representation.
        client_outpoints_json = json.loads(body.decode('utf-8'))
        if not isinstance(client_outpoints_json, list):
            raise web.HTTPBadRequest(reason="payload is not a list")
        for pushdata_hash_hex in client_outpoints_json:
            if not isinstance(pushdata_hash_hex, str):
                raise web.HTTPBadRequest(reason="one or more payload entries are incorrect")
            try:
                pushdata_hash = bytes.fromhex(pushdata_hash_hex)
            except (ValueError, TypeError):
                raise web.HTTPBadRequest(reason="one or more payload entries are incorrect")
            pushdata_hashes.add(pushdata_hash)
    elif content_type == 'application/octet-stream':
        if len(body) % 32 != 0:
            raise web.HTTPBadRequest(reason="binary request body malformed")

        for pushdata_index in range(len(body) // 32):
            pushdata_hashes.add(body[pushdata_index:pushdata_index+32])
        body_bytes = body
    else:
        raise web.HTTPBadRequest(reason="unknown request body content type")

    if not len(pushdata_hashes):
        raise web.HTTPBadRequest(reason="no pushdata hashes provided")

    # This is required to update all the given pushdata filtering registration from finalised
    # (and not being deleted by any other concurrent task) to finalised and being deleted. If
    # any of the registrations are not in this state, it is assumed that the client application
    # is broken and mismanaging it's own state.
    try:
        await app_state.database_context.run_in_thread_async(
            update_indexer_filtering_registrations_pushdatas_flags,
            account_id, list(pushdata_hashes),
            update_flags=IndexerPushdataRegistrationFlag.DELETING,
            filter_flags=IndexerPushdataRegistrationFlag.FINALISED,
            filter_mask=IndexerPushdataRegistrationFlag.MASK_FINALISED_DELETING_CLEAR,
            require_all=True)
    except DatabaseStateModifiedError:
        raise web.HTTPBadRequest(reason="some pushdata hashes are not registered")

    response: Optional[web.Response] = None
    try:
        # Pass on the registrations to the indexer. The indexer just supports binary as it is
        # not exposed publically, so we reserialise the hashes.
        if body_bytes is None:
            body_bytes = b"".join(pushdata_hashes)
        response = await mirrored_indexer_call_async(request, body=body_bytes)
    finally:
        if response is not None and response.status == http.HTTPStatus.OK:
            # The indexer applies the deregistrations successfully so we can update our state too.
            await app_state.database_context.run_in_thread_async(
                delete_indexer_filtering_registrations_pushdatas,
                account_id, list(pushdata_hashes), IndexerPushdataRegistrationFlag.FINALISED,
                IndexerPushdataRegistrationFlag.FINALISED)
        else:
            # The state change was not able to be applied on the indexer, so we remove the
            # `DELETING` state from the registrations.
            await app_state.database_context.run_in_thread_async(
                update_indexer_filtering_registrations_pushdatas_flags,
                account_id, list(pushdata_hashes),
                update_flags=IndexerPushdataRegistrationFlag.FINALISED,
                update_mask=IndexerPushdataRegistrationFlag.MASK_DELETING_CLEAR)
    assert response is not None
    return response


async def indexer_get_transaction(request: web.Request) -> web.Response:
    """
    Optional endpoint if running an indexer.

    Give the client access to arbitrary transactions from any running indexer.
    """
    # TODO(1.4.0) This should be monetised with a free quota.
    return await mirrored_indexer_call_async(request)


async def indexer_get_merkle_proof(request: web.Request) -> web.Response:
    """
    Optional endpoint if running an indexer.

    Give the client access to arbitrary merkle proofs from any running indexer.
    """
    # TODO(1.4.0) This should be monetised with a free quota.
    query_params: dict[str, str] = {}
    if request.query.get("includeFullTx") == "1":
        query_params["includeFullTx"] = "1"
    query_params["targetType"] = request.query.get("targetType", "hash")
    return await mirrored_indexer_call_async(request, query_params=query_params)


async def indexer_post_output_spends(request: web.Request) -> web.Response:
    """
    Optional endpoint if running an indexer.

    Give the client access to request arbitrary output spend data.
    """
    # TODO(1.4.0) This should be monetised with a free quota.
    return await mirrored_indexer_call_async(request)


async def indexer_post_output_spend_notifications(request: web.Request) -> web.Response:
    """
    Optional endpoint if running an indexer.

    Give the client access to request arbitrary output spend data and subscribe to notifications
    for any that have no entries. The client must be connected to the general web socket which
    is where the notifications will be routed.
    """
    # TODO(1.4.0) This should be monetised with a free quota.
    app_state: ApplicationState = request.app['app_state']
    body = await request.content.read()
    if not body:
        raise web.HTTPBadRequest(reason="no body")

    # For most of these requests, they are stateless in that the client is requesting some
    # data and will get it in the response. This request is stateful in that there the caller
    # is subscribing to notifications and we need to route those notifications to their web
    # socket. So instead of just proxying the body, we extract it and process it.
    client_outpoints: set[Outpoint] = set()
    content_type = request.headers.get("Content-Type")
    if content_type == 'application/json':
        # Convert the incoming JSON representation to the internal binary representation.
        client_outpoints_json = json.loads(body.decode('utf-8'))
        if not isinstance(client_outpoints_json, list):
            raise web.HTTPBadRequest(reason="payload is not a list")
        for entry in client_outpoints_json:
            if not isinstance(entry, list) or len(entry) != 2 or not isinstance(entry[1], int):
                raise web.HTTPBadRequest(reason="one or more payload entries are incorrect")
            try:
                tx_hash = hex_str_to_hash(entry[0])
            except (ValueError, TypeError):
                raise web.HTTPBadRequest(reason="one or more payload entries are incorrect")
            client_outpoints.add(Outpoint(tx_hash, entry[1]))
    elif content_type == 'application/octet-stream':
        if len(body) % outpoint_struct.size != 0:
            raise web.HTTPBadRequest(reason="binary request body malformed")

        for outpoint_index in range(len(body) // outpoint_struct.size):
            outpoint = cast(Outpoint,
                outpoint_struct.unpack_from(body, outpoint_index * outpoint_struct.size))
            client_outpoints.add(outpoint)
    else:
        raise web.HTTPBadRequest(reason="unknown request body content type")

    if not len(client_outpoints):
        raise web.HTTPBadRequest(reason="no outpoints provided")

    # TODO(1.4.0) Accounts. Until we have free quota accounts we need a way to
    #     access the server as if we were doing so with an account. This should be removed
    #     when we have proper account usage in ESV.
    assert app_state.temporary_account_id is not None
    account_id = app_state.temporary_account_id

    websocket_state = app_state.get_websocket_state_for_account_id(account_id)
    if websocket_state is None:
        raise web.HTTPBadRequest(reason="client account not connected to websocket")

    websocket_state.spent_output_registrations |= client_outpoints
    try:
        response = await mirrored_indexer_call_async(request, body=body)
    except aiohttp.ClientError:
        # aiohttp can raise any number of random exceptions. We can never be sure they won't
        # raise and we don't know what it can raise. Of course it is not documented.
        websocket_state.spent_output_registrations -= client_outpoints
        raise
    else:
        if response.status > http.HTTPStatus.ACCEPTED:
            websocket_state.spent_output_registrations -= client_outpoints
    return response


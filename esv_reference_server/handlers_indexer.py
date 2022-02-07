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
from bitcoinx import hex_str_to_hash

from .types import Outpoint, outpoint_struct

if TYPE_CHECKING:
    from .server import ApplicationState


logger = logging.getLogger("handlers-indexer")


async def mirrored_indexer_call_async(request: web.Request, *,
        body: Optional[bytes]=None, query_params: Optional[dict[str, str]]=None) -> web.Response:
    """
    The indexer functionality must be provided by the party who is running the reference server
    and exposed via the `INDEXER_URL` environment variable. This function mirrors calls made
    on reference server endpoints onto the given indexer instance.
    """
    client_session: aiohttp.ClientSession = request.app['client_session']
    app_state: ApplicationState = request.app['app_state']

    method_name = request.method.lower()
    if body is None and method_name == "post":
        body = await request.content.read()
        if not body:
            return web.Response(status=http.HTTPStatus.BAD_REQUEST, reason="no body provided")

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


async def indexer_post_pushdata_filter_matches(request: web.Request) -> web.Response:
    """
    Optional endpoint if running an indexer.

    Give the client access to any restoration index held by any running indexer.
    """
    # TODO(1.4.0) This should be monetised with a free quota.
    return await mirrored_indexer_call_async(request)


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


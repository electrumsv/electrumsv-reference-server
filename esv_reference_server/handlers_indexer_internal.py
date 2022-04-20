# Copyright(c) 2022 Bitcoin Association.
# Distributed under the Open BSV software license, see the accompanying file LICENSE
#
# The goal of this file is to allow non-public applications to have access to a secure API.

from http import HTTPStatus

from aiohttp import web

from .application_state import ApplicationState


async def indexer_post_tip_filter_matches(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app["app_state"]

    content_type = request.headers.get("Content-Type", "application/octet-stream")
    if content_type != "application/octet-stream":
        raise web.HTTPBadRequest(reason="Invalid 'Content-Type', "
            f"expected 'application/octet-stream', got '{content_type}'")

    # TODO(1.4.0) Unfinished code.

    return web.Response(status=HTTPStatus.OK, reason="OK")


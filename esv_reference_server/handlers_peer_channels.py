from __future__ import annotations

import os
import logging
from typing import Any, Dict, Optional, TYPE_CHECKING

import aiohttp
from aiohttp import web

from .constants import SERVER_HOST, SERVER_PORT


if TYPE_CHECKING:
    from .server import ApplicationState
    from .sqlite_db import SQLiteDatabase


logger = logging.getLogger('handlers')


async def list_channels(request: web.Request) -> web.Response:
    return web.HTTPNotImplemented()


async def get_single_channel_details(request: web.Request) -> web.Response:
    return web.HTTPNotImplemented()


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


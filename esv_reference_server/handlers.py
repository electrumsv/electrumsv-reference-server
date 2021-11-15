import typing

from aiohttp import web
import logging

if typing.TYPE_CHECKING:
    from esv_reference_server.server import ApplicationState
    from esv_reference_server.sqlite_db import SQLiteDatabase


logger = logging.getLogger('handlers')


async def ping(request: web.Request) -> web.Response:
    return web.Response(text="true")


async def error(request: web.Request) -> web.Response:
    raise ValueError("This is a test of raising an exception in the handler")


async def get_headers(request: web.Request) -> web.Response:
    raise NotImplementedError

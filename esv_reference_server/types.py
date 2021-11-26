from typing import NamedTuple

from aiohttp import web


class HeadersWSClient(NamedTuple):
    ws_id: str
    websocket: web.WebSocketResponse


class MsgBoxWSClient(NamedTuple):
    ws_id: str
    websocket: web.WebSocketResponse
    msg_box_internal_id: int
    accept_type: str  # http 'Accept' header (i.e. application/json vs application/octet-stream)

from typing import NamedTuple

from aiohttp import web


class HeadersWSClient(NamedTuple):
    ws_id: str
    websocket: web.WebSocketResponse


class MsgBoxWSClient(NamedTuple):
    ws_id: str
    websocket: web.WebSocketResponse
    channel_id: str  # 64 byte base64.urlsafe_b64decode
    accept_type: str  # http 'Accept' header (i.e. application/json vs application/octet-stream)

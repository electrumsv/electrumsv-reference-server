from typing import NamedTuple, TypedDict, Dict

from aiohttp import web


class HeadersWSClient(NamedTuple):
    ws_id: str
    websocket: web.WebSocketResponse


class MsgBoxWSClient(NamedTuple):
    ws_id: str
    websocket: web.WebSocketResponse
    msg_box_internal_id: int
    accept_type: str  # http 'Accept' header (i.e. application/json vs application/octet-stream)


class Route(NamedTuple):
    aiohttp_route_def: web.RouteDef
    auth_required: bool


class WebsocketError(TypedDict):
    reason: str
    status_code: int


class EndpointInfo(NamedTuple):
    http_method: str
    url: str
    auth_required: bool

from datetime import datetime
from typing import NamedTuple, TypedDict, Union

from aiohttp import web


class GeneralWSClient(NamedTuple):
    ws_id: str
    websocket: web.WebSocketResponse
    accept_type: str  # application/json or application/octet-stream


class HeadersWSClient(NamedTuple):
    ws_id: str
    websocket: web.WebSocketResponse


class MsgBoxWSClient(NamedTuple):
    ws_id: str
    websocket: web.WebSocketResponse
    msg_box_internal_id: int


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


class Header(TypedDict):
    hash: str
    version: int
    prevBlockHash: str
    merkleRoot: str
    creationTimestamp: int
    difficultyTarget: int
    nonce: int
    transactionCount: int
    work: int


class PushNotification(TypedDict):
    channel_id: int
    notification: str
    external_id: str  # general websocket needs this


class TipNotification(TypedDict):
    header: Header
    state: str
    chainWork: int
    height: int


class GeneralNotification(TypedDict):
    message_type: str
    result: Union[
        PushNotification,
        TipNotification
    ]

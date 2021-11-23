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


class ChannelRow(NamedTuple):
    internalid: int
    account_id: int
    externalid: str  # 64 byte base64.urlsafe_b64decode
    publicread: bool
    publicwrite: bool
    locked: bool
    sequenced: bool
    minagedays: int
    maxagedays: int
    autoprune: bool


class ChannelAPITokenRow(NamedTuple):
    id: int
    account_id: int
    channel_externalid: int
    token: str  # 64 byte base64.urlsafe_b64decode
    description: str
    canread: bool
    canwrite: bool
    validfrom: int
    validto: int

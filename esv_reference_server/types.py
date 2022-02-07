from __future__ import annotations
import dataclasses
import struct
import typing
from typing import Any, Literal, NamedTuple, Optional, TypedDict, Union

from aiohttp import web
from bitcoinx import hash_to_hex_str

from .constants import AccountMessageKind

if typing.TYPE_CHECKING:
    from .msg_box.models import MsgBox


# TODO Ideally these media types would be constants from some standard library.
AccountWebsocketMediaType = Union[Literal["application/json"], Literal["application/octet-stream"]]

@dataclasses.dataclass
class AccountWebsocketState:
    ws_id: str
    websocket: web.WebSocketResponse
    account_id: int
    accept_type: AccountWebsocketMediaType

    spent_output_registrations: set[Outpoint] = dataclasses.field(default_factory=set)


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
    msg_box: 'MsgBox'
    notification: str


class HeaderSVTip(TypedDict):
    header: Header
    state: str
    chainWork: int
    height: int


class ChannelNotification(TypedDict):
    id: str
    notification: str


class GeneralNotification(TypedDict):
    message_type: str
    result: Union[ChannelNotification, str]


class AccountMessage(NamedTuple):
    account_id: int
    message_kind: AccountMessageKind
    message: Any



class Outpoint(NamedTuple):
    tx_hash: bytes
    output_index: int

OUTPOINT_FORMAT = ">32sI"
outpoint_struct = struct.Struct(OUTPOINT_FORMAT)


class OutputSpend(NamedTuple):
    out_tx_hash: bytes
    out_index: int
    in_tx_hash: bytes
    in_index: int
    block_hash: Optional[bytes]

    def __repr__(self) -> str:
        return f'OutputSpend("{hash_to_hex_str(self.out_tx_hash)}", {self.out_index}, ' \
            f'"{hash_to_hex_str(self.in_tx_hash)}", {self.in_index}, ' + \
            (f'"{hash_to_hex_str(self.block_hash)}"' if self.block_hash else 'None') +')'

OUTPUT_SPEND_FORMAT = ">32sI32sI32s"
output_spend_struct = struct.Struct(OUTPUT_SPEND_FORMAT)


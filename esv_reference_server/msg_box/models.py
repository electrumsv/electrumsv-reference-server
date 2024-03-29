"""
Copyright(c) 2021 Bitcoin Association.
Distributed under the Open BSV software license, see the accompanying file LICENSE
"""
from datetime import datetime
from typing import NamedTuple

from ..constants import MessageBoxTokenFlag


class MsgBoxAPITokenRow(NamedTuple):
    id: int
    account_id: int
    msg_box_id: int
    token: str  # 64 byte base64.urlsafe_b64decode
    description: str
    flags: MessageBoxTokenFlag
    validfrom: int  # time.time()
    validto: int|None  # time.time()

class MsgBox(NamedTuple):
    id: int
    account_id: int  # owner
    external_id: str  # 64 byte base64.urlsafe_b64decode
    public_read: bool
    public_write: bool
    locked: bool
    sequenced: bool
    min_age_days: int
    max_age_days: int
    autoprune: bool
    api_tokens: list[MsgBoxAPITokenRow]
    head_message_sequence: int


class MsgBoxRow(NamedTuple):
    # id: int - autoincrement id
    account_id: int  # aka "Owner" in SPV Channels ref. implementation
    externalid: str  # 64 byte base64.urlsafe_b64decode
    publicread: bool
    publicwrite: bool
    locked: bool
    sequenced: bool
    minagedays: int
    maxagedays: int
    autoprune: bool


class Message(NamedTuple):
    msg_box_id: int
    msg_box_api_token_id: int
    content_type: str
    payload: bytes
    received_ts: int  # time.time()


class MessageMetadata(NamedTuple):
    id: int
    msg_box_id: int
    msg_box_api_token_id: int
    content_type: str
    received_ts: datetime

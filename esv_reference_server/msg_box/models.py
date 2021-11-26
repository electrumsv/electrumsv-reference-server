"""
Copyright(c) 2021 Bitcoin Association.
Distributed under the Open BSV software license, see the accompanying file LICENSE
"""
from dataclasses import dataclass
from datetime import datetime
from typing import NamedTuple, Optional


@dataclass(slots=True)
class MsgBoxAPIToken:
    id: int
    account_id: int
    msg_box_id: int
    token: str  # 64 byte base64.urlsafe_b64decode
    # fcm_tokens: list[FCMToken] - not implemented
    description: str
    can_read: bool
    can_write: bool
    valid_from: datetime
    valid_to: Optional[datetime]



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
    api_tokens: list[MsgBoxAPIToken]
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


class MsgBoxAPITokenRow(NamedTuple):
    # id: int - autoincrement id
    account_id: int
    msg_box_id: int
    token: str  # 64 byte base64.urlsafe_b64decode
    description: str
    canread: bool
    canwrite: bool
    validfrom: datetime


class Message(NamedTuple):
    msg_box_id: int
    msg_box_api_token_id: int
    content_type: str
    payload: bytes
    received_ts: datetime


class MessageMetadata(NamedTuple):
    id: int
    msg_box_id: int
    msg_box_api_token_id: int
    content_type: str
    received_ts: datetime


class PushNotification(NamedTuple):
    msg_box: MsgBox
    notification_new_message_text: str
    received_ts: datetime

    def to_dict(self):
        return {
            "channel_id": self.msg_box.id,
            "notification": self.notification_new_message_text,
            "received": self.received_ts.isoformat()
        }

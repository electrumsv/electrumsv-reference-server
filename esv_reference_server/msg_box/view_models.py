"""
Copyright(c) 2021 Bitcoin Association.
Distributed under the Open BSV software license, see the accompanying file LICENSE
"""
from dataclasses import dataclass
from datetime import datetime
from typing import TypedDict, Dict, Union, cast, List

from esv_reference_server.msg_box.models import MsgBox


class RetentionViewModelJSON(TypedDict):
    min_age_days: int
    max_age_days: int
    auto_prune: bool


@dataclass()
class RetentionViewModel:
    min_age_days: int
    max_age_days: int
    auto_prune: bool

    def is_valid(self) -> bool:
        if self.min_age_days is not None and \
                self.max_age_days is not None and \
                self.min_age_days > self.max_age_days:
            return False
        return True


@dataclass
class MsgBoxAPITokenViewModelGet:
    id: int
    token: str
    description: str
    can_read: bool
    can_write: bool


@dataclass()
class MsgBoxViewModelCreate:
    public_read: bool
    public_write: bool
    sequenced: bool
    retention: RetentionViewModel

    @classmethod
    def from_request(cls, request_body: Dict[str, Union[bool, RetentionViewModelJSON]]) \
            -> 'MsgBoxViewModelCreate':
        retention: RetentionViewModelJSON = cast(RetentionViewModelJSON, request_body['retention'])
        return cls(
            public_read=bool(request_body['public_read']),
            public_write=bool(request_body['public_write']),
            sequenced=bool(request_body['sequenced']),
            retention=RetentionViewModel(
                min_age_days=retention['min_age_days'],
                max_age_days=retention['max_age_days'],
                auto_prune=retention['auto_prune'])
        )


@dataclass
class MsgBoxViewModelAmend:
    public_read: bool
    public_write: bool
    locked: bool

    @classmethod
    def from_request(cls, request_body: Dict[str, bool]) -> 'MsgBoxViewModelAmend':
        klass: MsgBoxViewModelAmend = cls(
            public_read=bool(request_body['public_read']),
            public_write=bool(request_body['public_write']),
            locked=bool(request_body['locked']),
        )
        return klass


@dataclass()
class MsgBoxViewModelGet:
    id: str
    href: str
    public_read: bool
    public_write: bool
    sequenced: bool
    locked: bool
    head_sequence: int
    retention: RetentionViewModel
    access_tokens: List[MsgBoxAPITokenViewModelGet]

    @classmethod
    def from_msg_box(cls, msg_box: MsgBox, href: str) -> 'MsgBoxViewModelGet':
        retention = RetentionViewModel(auto_prune=msg_box.autoprune,
            min_age_days=msg_box.min_age_days, max_age_days=msg_box.max_age_days)

        api_tokens = [
            MsgBoxAPITokenViewModelGet(
                api_token.id,
                api_token.token,
                api_token.description if api_token.description else "Owner",
                bool(api_token.can_read),
                bool(api_token.can_write)
            )
            for api_token in msg_box.api_tokens
        ]

        return cls(id=msg_box.external_id, href=href, public_read=bool(msg_box.public_read),
            public_write=bool(msg_box.public_write), sequenced=bool(msg_box.sequenced),
            locked=bool(msg_box.locked), head_sequence=msg_box.head_message_sequence,
            retention=retention, access_tokens=api_tokens)


@dataclass()
class APITokenViewModelCreate:
    description: str
    can_read: bool
    can_write: bool


class APITokenViewModelGetJSON(TypedDict):
    id: int
    token: str
    description: str
    can_read: bool
    can_write: bool


@dataclass()
class APITokenViewModelGet:
    id: int
    token: str
    description: str
    can_read: bool
    can_write: bool


# These are both for json but they represent an
# underlying json vs binary message
class MessageViewModelGetJSON(TypedDict):
    sequence: int
    received: str
    content_type: str
    payload: str


class MessageViewModelGetBinary(TypedDict):
    sequence: int
    received: str
    content_type: str
    payload: str  # hex


@dataclass()
class MessageViewModelGet:
    sequence: int
    received: datetime
    content_type: str
    payload: bytes

    def to_dict(self) -> Union[MessageViewModelGetJSON, MessageViewModelGetBinary]:
        if self.content_type == 'application/json':
            return MessageViewModelGetJSON(
                sequence=self.sequence,
                received=self.received.isoformat(),
                content_type=self.content_type,
                payload=self.payload.decode('utf-8')
            )
        else:
            return MessageViewModelGetBinary(
                sequence=self.sequence,
                received=self.received.isoformat(),
                content_type=self.content_type,
                payload=self.payload.hex()
            )

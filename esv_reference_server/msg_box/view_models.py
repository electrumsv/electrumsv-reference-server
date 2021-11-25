import json
from dataclasses import dataclass
from datetime import datetime

from esv_reference_server.msg_box.models import MsgBoxAPIToken, MsgBox


@dataclass(slots=True)  # slots=True support was added in python 3.10.x
class RetentionViewModel:
    min_age_days: int
    max_age_days: int
    auto_prune: bool

    def is_valid(self):
        if self.min_age_days is not None and \
                self.max_age_days is not None and \
                self.min_age_days > self.max_age_days:
            return False
        return True

    def to_dict(self):
        return {
            "min_age_days": self.min_age_days,
            "max_age_days": self.max_age_days,
            "auto_prune": bool(self.auto_prune)
        }


@dataclass
class MsgBoxAPITokenViewModelGet:
    id: int
    token: str
    description: str
    can_read: bool
    can_write: bool

    def to_dict(self):
        return {
            "id": self.id,
            "token": self.token,
            "description": "Owner",
            "can_read": bool(self.can_read),
            "can_write": bool(self.can_write)
        }


@dataclass(slots=True)
class MsgBoxViewModelCreate:
    public_read: bool
    public_write: bool
    sequenced: bool
    retention: RetentionViewModel

    @classmethod
    def from_request(cls, request_body: dict):
        return cls(
            public_read=bool(request_body['public_read']),
            public_write=bool(request_body['public_write']),
            sequenced=bool(request_body['sequenced']),
            retention=RetentionViewModel(**request_body['retention'])
        )


@dataclass(slots=True)
class MsgBoxViewModelAmend:
    public_read: bool
    public_write: bool
    locked: bool

    @classmethod
    def from_request(cls, request_body: dict):
        return cls(
            public_read=bool(request_body['public_read']),
            public_write=bool(request_body['public_write']),
            locked=bool(request_body['locked']),
        )

    def to_dict(self):
        return {
            "public_read": bool(self.public_read),
            "public_write": bool(self.public_write),
            "locked": bool(self.locked),
    }


@dataclass(slots=True)
class MsgBoxViewModelGet:
    external_id: str
    href: str
    public_read: bool
    public_write: bool
    sequenced: bool
    locked: bool
    head_sequence: int
    retention: RetentionViewModel
    api_tokens: list[MsgBoxAPITokenViewModelGet]

    def to_dict(self):
        return {
            "id": self.external_id,
            "href": self.href,
            "public_read": bool(self.public_read),
            "public_write": bool(self.public_write),
            "sequenced": bool(self.sequenced),
            "locked": bool(self.locked),
            "head": self.head_sequence,
            "retention": self.retention.to_dict(),
            "access_tokens": [api_token.to_dict() for api_token in self.api_tokens]
    }

    @classmethod
    def from_msg_box(cls, msg_box: MsgBox, href: str):
        retention = RetentionViewModel(auto_prune=msg_box.autoprune,
            min_age_days=msg_box.min_age_days, max_age_days=msg_box.max_age_days)

        api_tokens = [MsgBoxAPITokenViewModelGet(api_token.id, api_token.token,
            api_token.description, api_token.can_read, api_token.can_write)
            for api_token in msg_box.api_tokens]

        return cls(external_id=msg_box.external_id, href=href, public_read=msg_box.public_read,
            public_write=msg_box.public_write, sequenced=msg_box.sequenced, locked=msg_box.locked,
            head_sequence=msg_box.head_message_sequence, retention=retention,
            api_tokens=api_tokens)


@dataclass(slots=True)
class APITokenViewModelCreate:
    description: str
    can_read: bool
    can_write: bool


@dataclass(slots=True)
class APITokenViewModelGet:
    id: str
    token: str
    description: str
    can_read: bool
    can_write: bool

    def to_dict(self):
        return {
            "id": self.id,
            "token": self.token,
            "description": self.description,
            "can_read": bool(self.can_write),
            "can_write": bool(self.can_read)
        }


@dataclass(slots=True)
class MessageViewModelGet:
    sequence: int
    received: datetime
    content_type: str
    payload: bytes

    def to_dict(self):
        if self.content_type == 'application/json':
            return {
                "sequence": self.sequence,
                "received": self.received.isoformat(),
                "content_type": self.content_type,
                "payload": json.loads(self.payload)
            }
        else:
            return {
                "sequence": self.sequence,
                "received": self.received.isoformat(),
                "content_type": self.content_type,
                "payload": self.payload.hex()
            }

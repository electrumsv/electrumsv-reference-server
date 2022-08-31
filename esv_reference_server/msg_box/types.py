import dataclasses
from typing import TypedDict


@dataclasses.dataclass
class MessageRow:
    message_id: int
    from_token_id: int
    message_box_id: int
    sequence: int
    date_received: int
    content_type: str
    payload_bytes: bytes


class MessageTextResponse(TypedDict):
    sequence: int
    received: str
    content_type: str
    payload: str

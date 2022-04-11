from __future__ import annotations
import base64
import json
import os
import struct
from typing import Any, Optional

from aiohttp import web

from .constants import AccountMessageKind


def create_external_id() -> str:
    rnd_bytes = os.urandom(64)
    return base64.urlsafe_b64encode(rnd_bytes).decode('utf-8')


create_account_api_token = create_external_id  # one of these master bearer tokens per account
create_channel_api_token = create_external_id


def _try_read_bearer_token(request: web.Request) -> Optional[str]:
    auth_string = request.headers.get('Authorization', None)
    if auth_string is None or not auth_string.startswith("Bearer "):
        return None
    api_key = auth_string[7:]
    return api_key


def _try_read_bearer_token_from_query(request: web.Request) -> Optional[str]:
    # No "Bearer " prefix
    auth_string = request.query.get('token', None)
    if auth_string is None:
        return None
    return auth_string


def pack_account_message_bytes(message_kind: AccountMessageKind, message_data: Any) -> bytes:
    """
    Serialise an outgoing account message as bytes.
    """
    message_bytes = struct.pack(">I", message_kind)
    if message_kind == AccountMessageKind.PEER_CHANNEL_MESSAGE:
        # Just use the same JSON format for now.
        assert isinstance(message_data, dict)
        message_bytes += json.dumps(message_data).encode()
    elif message_kind == AccountMessageKind.SPENT_OUTPUT_EVENT:
        assert isinstance(message_data, bytes)
        message_bytes += message_data
    else:
        raise NotImplementedError(f"Packing message kind {message_kind} is unsupported")
    return message_bytes

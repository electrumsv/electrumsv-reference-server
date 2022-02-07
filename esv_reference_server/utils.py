import json
import struct
from typing import Any, Optional, TYPE_CHECKING

from aiohttp import web

from .constants import AccountMessageKind
from .types import ChannelNotification

if TYPE_CHECKING:
    from .sqlite_db import SQLiteDatabase


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


def _auth_ok(api_key: str, db: 'SQLiteDatabase') -> bool:
    account_id, _account_flags = db.get_account_id_for_api_key(api_key)
    if account_id is None:
        return False
    return True


def pack_account_message_bytes(message_kind: AccountMessageKind, message_data: Any) -> bytes:
    """
    Serialise an outgoing account message as bytes.
    """
    message_bytes = struct.pack(">I", message_kind)
    if message_kind == AccountMessageKind.PEER_CHANNEL_MESSAGE:
        # Just use the same JSON format for now.
        assert isinstance(message_data, ChannelNotification)
        message_bytes += json.dumps(message_data).encode()
    elif message_kind == AccountMessageKind.SPENT_OUTPUT_EVENT:
        assert isinstance(message_data, bytes)
        message_bytes += message_data
    else:
        raise NotImplementedError(f"Packing message kind {message_kind} is unsupported")
    return message_bytes

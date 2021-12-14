from typing import Optional

import typing
from aiohttp import web

if typing.TYPE_CHECKING:
    from esv_reference_server.sqlite_db import SQLiteDatabase


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

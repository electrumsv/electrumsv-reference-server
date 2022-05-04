"""
Copyright(c) 2021 Bitcoin Association.
Distributed under the Open BSV software license, see the accompanying file LICENSE
"""
from enum import IntEnum

from typing import Dict

from esv_reference_server.types import WebsocketError


class APIErrors(IntEnum):
    CHANNEL_LOCKED = 10001
    SEQUENCING_FAILURE = 10002
    DATABASE_WRITE_FAILURE = 10003
    INVALID_TIP_FILTER_CALLBACK = 10004
    PEER_CHANNEL_TOKEN_EXPIRED = 10005
    PAYMENT_CHANNEL_INVALID = 10006
    RETENTION_INVALID_MIN_MAX = 10007
    INTERNAL_SERVER_ERROR = 10008
    PAYLOAD_TOO_LARGE = 10009
    UNSUPPORTED_ACCEPT_HEADER = 10010
    PEER_CHANNEL_TOKEN_NOT_FOUND = 10011
    MESSAGES_NOT_FOUND = 10012
    SEQUENCE_NUMBER_NOT_PROVIDED = 10013
    SEQUENCE_NUMBER_NOT_FOUND = 10014
    MESSAGE_METADATA_NOT_FOUND = 10015
    MESSAGE_BOX_NOT_FOUND = 10016
    RETENTION_NOT_YET_EXPIRED = 10017
    MISSING_QUERY_PARAM = 10018
    MISSING_MULTIPART_PAYLOAD = 10019
    MISSING_HEADER = 10020
    MISSING_PATH_PARAMETER = 10021
    INVALID_MULTIPART_PAYLOAD = 10022
    INVALID_BEARER_TOKEN = 10023
    PUSHDATA_HASHES_ALREADY_REGISTERED = 10024
    PUSHDATA_HASHES_NOT_REGISTERED = 10025
    INDEXER_UNAVAILABLE = 10026
    INVALID_TRANSACTION = 10027
    BROKEN_PAYMENT_CHANNEL = 10028
    CHANNEL_STATE_INCONSISTENCY = 10029
    ACCOUNT_STATE_INCONSISTENCY = 10030
    MAPI_BROADCAST_FAILURE = 10031
    TOKEN_VALIDATION_ERROR_TOO_SHORT = 10032
    TOKEN_VALIDATION_ERROR_INVALID = 10033


class WebsocketUnauthorizedException(Exception):
    pass


class Error(Exception):

    def __init__(self, reason: str, status: int):
        self.reason = reason
        self.status = status

    def to_websocket_dict(self) -> Dict[str, WebsocketError]:
        return {"error": {"reason": self.reason,
                          "status_code": self.status}}

    @classmethod
    def from_websocket_dict(cls, message: Dict[str, WebsocketError]) -> 'Error':
        reason = message["error"]["reason"]
        status = message["error"]["status_code"]
        return cls(reason, status)

    def __str__(self) -> str:
        return f"Error(reason={self.reason}, status={self.status})"

"""
Copyright(c) 2021 Bitcoin Association.
Distributed under the Open BSV software license, see the accompanying file LICENSE
"""

from aiohttp.web_exceptions import HTTPForbidden, HTTPBadRequest, HTTPConflict


class Error(Exception):

    def __init__(self, reason: str, status: int):
        self.reason = reason
        self.status = status

    def to_websocket_dict(self):
        return {"error": {"reason": self.reason,
                          "status_code": self.status}}

    @classmethod
    def from_websocket_dict(cls, message: dict):
        reason = message["error"]["reason"]
        status = message["error"]["status_code"]
        return cls(reason, status)

    def __str__(self):
        return f"Error(reason={self.reason}, status={self.status})"


NoBearerToken = Error(
    reason="No 'Bearer' authentication",
    status=HTTPBadRequest.status_code)
RetentionInvalidMinMax = Error(
    reason="Invalid retention: max days should be greater than min days.",
    status=HTTPBadRequest.status_code)
RetentionNotExpired = Error(
    reason="Retention period has not yet expired.",
    status=HTTPBadRequest.status_code)
ChannelLocked = Error(
    reason="Retention period has not yet expired.",
    status=HTTPForbidden.status_code)
SequencingFailure = Error(
    reason="Sequencing Failure.",
    status=HTTPConflict.status_code)

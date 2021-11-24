from typing import NamedTuple
from aiohttp.web_exceptions import HTTPForbidden, HTTPBadRequest, HTTPConflict


class Error(NamedTuple):
    reason: str
    status: int


NoBearerToken = Error(reason="No 'Bearer' authentication", status=HTTPBadRequest.status_code)
RetentionInvalidMinMax = Error(reason="Invalid retention: max days should be greater than min days.", status=HTTPBadRequest.status_code)
RetentionNotExpired = Error(reason="Retention period has not yet expired.", status=HTTPBadRequest.status_code)
ChannelLocked = Error(reason="Retention period has not yet expired.", status=HTTPForbidden.status_code)
SequencingFailure = Error(reason="Sequencing Failure.", status=HTTPConflict.status_code)

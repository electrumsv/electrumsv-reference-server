# Copyright(c) 2022 Bitcoin Association.
# Distributed under the Open BSV software license, see the accompanying file LICENSE
#
# The goal of this file is to allow non-public applications to have access to a secure API.

import re
from typing import Optional, Set
import urllib.parse

from esv_reference_server.errors import APIErrors


class TokenValidationError(Exception):

    def __init__(self, code: APIErrors):
        self.code = code


AUTHORIZATION_HEADER_VALUE_REGEX = re.compile("^[ -~]+$", re.ASCII)


def len_stripped_text(text: str) -> int:
    stripped_text = text.replace(" ", "")
    return len(stripped_text)


def validate_authorization_header(text: str) -> None:
    if len_stripped_text(text) < 8:
        raise TokenValidationError(APIErrors.TOKEN_VALIDATION_ERROR_TOO_SHORT)
    match = AUTHORIZATION_HEADER_VALUE_REGEX.match(text)
    if match is None:
        raise TokenValidationError(APIErrors.TOKEN_VALIDATION_ERROR_INVALID)



## The following code (albeit modified) is from the given URL and their license applies.
##   https://stackoverflow.com/a/55827638


class UrlValidationError(Exception):
    ...


# Check https://regex101.com/r/A326u1/5 for reference
DOMAIN_FORMAT = re.compile(
    # http basic authentication [optional]
    r"(?:^(\w{1,255}):(.{1,255})@|^)"
    # check full domain length to be less than or equal to 253 (starting after http basic auth,
    # stopping before port)
    r"(?:(?:(?=\S{0,253}(?:$|:))"
    # check for at least one subdomain (maximum length per subdomain: 63 characters), dashes
    # in between allowed
    r"((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    # check for top level domain, no dashes allowed
    r"(?:[a-z0-9]{1,63})))"
    # accept also "localhost" only
    r"|localhost)"
    # port [optional]
    r"(:\d{1,5})?",
    re.IGNORECASE
)
DEFAULT_SCHEMES = { "http", "https" }

def validate_url(url: str, schemes: Optional[Set[str]]=None, allow_path: bool=False,
        allow_params: bool=False, allow_query: bool=False, allow_fragment: bool=False) -> str:
    if schemes is None:
        schemes = DEFAULT_SCHEMES

    url = url.strip()

    if not url:
        raise UrlValidationError("No URL specified")

    if len(url) > 2048:
        raise UrlValidationError("Too long")

    result = urllib.parse.urlparse(url)

    scheme = result.scheme
    domain = result.netloc

    if not scheme:
        raise UrlValidationError("Scheme not found")

    if scheme.lower() not in schemes:
        raise UrlValidationError("Invalid scheme")

    if not domain:
        raise UrlValidationError("Host not found")

    if not re.fullmatch(DOMAIN_FORMAT, domain):
        raise UrlValidationError("Invalid host")

    if not allow_path and result.path not in ("", "/"):
        raise UrlValidationError("URL contains a path")

    if not allow_params and result.params:
        raise UrlValidationError("URL contains params")

    if not allow_query and result.query:
        raise UrlValidationError("URL contains fragment")

    if not allow_fragment and result.fragment:
        raise UrlValidationError("URL contains query")

    return url

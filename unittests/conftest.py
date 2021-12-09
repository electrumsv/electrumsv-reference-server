import json
from typing import Optional

import requests


def _no_auth(url: str, method: str):
    assert method.lower() in {'get', 'post', 'head', 'delete', 'put'}
    request_call = getattr(requests, method.lower())
    result = request_call(url)
    assert result.status_code == 400, result.reason
    assert result.reason is not None  # {"authorization": "is required"}


def _wrong_auth_type(url: str, method: str):
    assert method.lower() in {'get', 'post', 'head', 'delete', 'put'}
    request_call = getattr(requests, method.lower())
    # No auth -> 400 {"authorization": "is required"}
    headers = {}
    headers["Authorization"] = "Basic xyz"
    result = request_call(url, headers=headers)
    assert result.status_code == 400, result.reason
    assert result.reason is not None


def _unauthorized(url: str, method: str, headers: Optional[dict] = None,
                  body: Optional[dict] = None):
    assert method.lower() in {'get', 'post', 'head', 'delete', 'put'}
    request_call = getattr(requests, method.lower())
    if not headers:
        headers = {}
    headers["Authorization"] = "Bearer <bad bearer token>"
    result = request_call(url, headers=headers, json=body)
    assert result.status_code == 401, result.reason
    assert result.reason is not None


def _successful_call(url: str, method: str, headers: Optional[dict] = None,
                     request_body: Optional[dict] = None, good_bearer_token: Optional[str] = None):
    assert method.lower() in {'get', 'post', 'head', 'delete', 'put'}
    request_call = getattr(requests, method.lower())
    if not headers:
        headers = {}
    headers["Authorization"] = f"Bearer {good_bearer_token}"
    return request_call(url, data=json.dumps(request_body), headers=headers)

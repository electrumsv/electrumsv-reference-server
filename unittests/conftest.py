import asyncio
import json
import os
import sys
import threading
from pathlib import Path
from typing import Optional
import requests
from aiohttp.abc import Application
from bitcoinx import PublicKey, PrivateKey

from server import AiohttpServer, logger, get_app

TEST_HOST = "127.0.0.1"
TEST_PORT = 52462
WS_URL_TEMPLATE_MSG_BOX = "http://localhost:52462/api/v1/channel/{channelid}/notify"

PRIVATE_KEY_1 = PrivateKey.from_hex(
    "720f1987db69efa562b3dabd78e51f19bd8da76c70ad839b72b939f4071b144b")
PUBLIC_KEY_1: PublicKey = PRIVATE_KEY_1.public_key

REF_TYPE_OUTPUT = 0
REF_TYPE_INPUT = 1
STREAM_TERMINATION_BYTE = b"\x00"

TEST_MASTER_BEARER_TOKEN = "t80Dp_dIk1kqkHK3P9R5cpDf67JfmNixNscexEYG0_xaCbYXKGNm4V_2HKr68ES5bytZ8F19IS0XbJlq41accQ=="
MODULE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))

CHANNEL_ID: str = ""
CHANNEL_BEARER_TOKEN: str = ""
CHANNEL_BEARER_TOKEN_ID: int = 0
CHANNEL_READ_ONLY_TOKEN: str = ""
CHANNEL_READ_ONLY_TOKEN_ID: int = 0



async def main(app: Application, host: str, port: int):
    server = AiohttpServer(app, host, port)
    try:
        await server.start()
    finally:
        await server.stop()


def electrumsv_reference_server_thread(app: Application, host: str = TEST_HOST,
        port: int = TEST_PORT):
    """Launches the ESV-Reference-Server to run in the background but with a test database"""
    try:
        asyncio.run(main(app, host, port))
        sys.exit(0)
    except KeyboardInterrupt:
        logger.debug("ElectrumSV Reference Server stopped")
    except Exception:
        logger.exception("unexpected exception in __main__")
    finally:
        logger.info("ElectrumSV Reference Server stopped")


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


def _bad_token(url: str, method: str, headers: Optional[dict] = None,
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
    if good_bearer_token:
        headers["Authorization"] = f"Bearer {good_bearer_token}"
    return request_call(url, data=json.dumps(request_body), headers=headers)


os.environ['EXPOSE_HEADER_SV_APIS'] = '1'
os.environ['HEADER_SV_URL'] = 'http://127.0.0.1:8080'
os.environ['SKIP_DOTENV_FILE'] = '1'
os.environ['REFERENCE_SERVER_RESET'] = '1'
os.environ['DATASTORE_LOCATION'] = str(MODULE_DIR.joinpath("test_sqlite.sqlite"))
os.environ['NOTIFICATION_TEXT_NEW_MESSAGE'] = 'New message arrived'
os.environ['MAX_MESSAGE_CONTENT_LENGTH'] = '65536'
os.environ['CHUNKED_BUFFER_SIZE'] = '1024'

app, host, port = get_app(TEST_HOST, TEST_PORT)
API_ROUTE_DEFS = app.API_ROUTE_DEFS
# for route in self.API_ROUTE_DEFS.items():
#     print(route)

thread = threading.Thread(target=electrumsv_reference_server_thread, args=(app, host, port),
            daemon=True)
thread.start()

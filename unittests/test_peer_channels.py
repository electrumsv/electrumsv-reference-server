import asyncio
import base64
import datetime
import json
import logging
import os
import sys
import threading
from pathlib import Path
from typing import Optional

import aiohttp
import pytest
import requests
from aiohttp import web
from aiohttp.web_app import Application
from bitcoinx import PrivateKey, PublicKey

from esv_client.client import WS_URL_TEMPLATE_MSG_BOX
from esv_reference_server.errors import Error
from esv_reference_server.sqlite_db import SQLiteDatabase
from server import logger, AiohttpServer, get_app

TEST_HOST = "127.0.0.1"
TEST_PORT = 52462

PRIVATE_KEY_1 = PrivateKey.from_hex(
    "720f1987db69efa562b3dabd78e51f19bd8da76c70ad839b72b939f4071b144b")
PUBLIC_KEY_1: PublicKey = PRIVATE_KEY_1.public_key

REF_TYPE_OUTPUT = 0
REF_TYPE_INPUT = 1
STREAM_TERMINATION_BYTE = b"\x00"

TEST_MASTER_BEARER_TOKEN = "t80Dp_dIk1kqkHK3P9R5cpDf67JfmNixNscexEYG0_xaCbYXKGNm4V_2HKr68ES5bytZ8F19IS0XbJlq41accQ=="
MODULE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))

CHANNEL_ID = None
CHANNEL_BEARER_TOKEN = None
CHANNEL_NEW_TOKEN = None
TOKEN_ID = 1


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


class TestAiohttpRESTAPI:

    @classmethod
    def setup_class(self) -> None:
        os.environ['SKIP_DOTENV_FILE'] = '1'
        os.environ['REFERENCE_SERVER_RESET'] = '1'
        os.environ['DATASTORE_LOCATION'] = str(MODULE_DIR.joinpath("test_sqlite.sqlite"))
        os.environ['NOTIFICATION_TEXT_NEW_MESSAGE'] = 'New message arrived'
        os.environ['MAX_MESSAGE_CONTENT_LENGTH'] = '65536'
        os.environ['CHUNKED_BUFFER_SIZE'] = '1024'

        self.app, host, port = get_app(TEST_HOST, TEST_PORT)
        self.API_ROUTE_DEFS = self.app.API_ROUTE_DEFS
        # for route in self.API_ROUTE_DEFS.items():
        #     print(route)

        thread = threading.Thread(target=electrumsv_reference_server_thread, args=(self.app, host, port),
            daemon=True)
        thread.start()

        self.logger = logging.getLogger("TestAiohttpRESTAPI")
        logging.basicConfig(format='%(asctime)s %(levelname)-8s %(name)-24s %(message)s',
            level=logging.DEBUG, datefmt='%Y-%m-%d %H:%M:%S')

        sqlite_db: SQLiteDatabase = self.app['app_state'].sqlite_db
        self.account_id, api_key = sqlite_db.create_account(
            public_key_bytes=PUBLIC_KEY_1.to_bytes())
        assert self.account_id == 2
        assert len(base64.urlsafe_b64decode(api_key)) == 64
        assert isinstance(api_key, str)
        global TEST_MASTER_BEARER_TOKEN
        TEST_MASTER_BEARER_TOKEN = api_key

    def setup_method(self) -> None:
        pass

    def teardown_method(self) -> None:
        pass

    @classmethod
    def teardown_class(self) -> None:
        pass

    def _no_auth(self, url: str, method: str):
        assert method.lower() in {'get', 'post', 'head', 'delete', 'put'}
        request_call = getattr(requests, method.lower())
        result = request_call(url)
        assert result.status_code == 400, result.reason
        assert result.reason is not None  # {"authorization": "is required"}

    def _wrong_auth_type(self, url: str, method: str):
        assert method.lower() in {'get', 'post', 'head', 'delete', 'put'}
        request_call = getattr(requests, method.lower())
        # No auth -> 400 {"authorization": "is required"}
        headers = {}
        headers["Authorization"] = "Basic xyz"
        result = request_call(url, headers=headers)
        assert result.status_code == 400, result.reason
        assert result.reason is not None

    def _unauthorized(self, url: str, method: str, headers: Optional[dict]= None,
            body: Optional[dict]= None):
        assert method.lower() in {'get', 'post', 'head', 'delete', 'put'}
        request_call = getattr(requests, method.lower())
        if not headers:
            headers = {}
        headers["Authorization"] = "Bearer <bad bearer token>"
        result = request_call(url, headers=headers, json=body)
        assert result.status_code == 401, result.reason
        assert result.reason is not None

    def _successful_call(self, url: str, method: str, headers: Optional[dict]=None,
            request_body: Optional[dict]=None, good_bearer_token: Optional[str]=None):
        assert method.lower() in {'get', 'post', 'head', 'delete', 'put'}
        request_call = getattr(requests, method.lower())
        if not headers:
            headers = {}
        headers["Authorization"] = f"Bearer {good_bearer_token}"
        return request_call(url, data=json.dumps(request_body), headers=headers)

    def test_ping(self):
        route = self.API_ROUTE_DEFS['ping']
        result = requests.get(route.url)
        assert result.text is not None

    def test_create_new_channel(self):
        route = self.API_ROUTE_DEFS['create_new_channel']
        if route.auth_required:
            self._no_auth(route.url, route.http_method)
            self._wrong_auth_type(route.url, route.http_method)
            self._unauthorized(route.url, route.http_method)

        request_body = {
            "public_read": True,
            "public_write": True,
            "sequenced": True,
            "retention": {
                "min_age_days": 0,
                "max_age_days": 0,
                "auto_prune": True
            }
        }
        self.logger.debug(f"test_create_new_channel url: {route.url}")
        result: requests.Response = self._successful_call(route.url, route.http_method, None,
            request_body, TEST_MASTER_BEARER_TOKEN)

        assert result.status_code == 200, result.reason

        response_body = result.json()
        # self.logger.debug(json.dumps(response_body, indent=4))

        single_channel_data = response_body
        global CHANNEL_ID
        global CHANNEL_BEARER_TOKEN
        CHANNEL_ID = single_channel_data['id']
        assert single_channel_data['href'] == f"http://{TEST_HOST}:{TEST_PORT}/api/v1/channel/{CHANNEL_ID}"
        assert single_channel_data['public_read'] is True
        assert single_channel_data['public_write'] is True
        assert single_channel_data['sequenced'] is True
        assert single_channel_data['retention'] == {"min_age_days": 0, "max_age_days": 0, "auto_prune": True}
        assert isinstance(single_channel_data['access_tokens'], list)
        assert single_channel_data['access_tokens'][0]['id'] == 1
        issued_token_bytes = base64.urlsafe_b64decode(single_channel_data['access_tokens'][0]['token'])
        assert len(issued_token_bytes) == 64
        assert single_channel_data['access_tokens'][0]['description'] == "Owner"
        CHANNEL_BEARER_TOKEN = single_channel_data['access_tokens'][0]['token']
        assert single_channel_data['access_tokens'][0]['can_read'] is True
        assert single_channel_data['access_tokens'][0]['can_write'] is True

    def test_list_channels(self):
        route = self.API_ROUTE_DEFS['list_channels']
        if route.auth_required:
            self._no_auth(route.url, route.http_method)
            self._wrong_auth_type(route.url, route.http_method)
            self._unauthorized(route.url, route.http_method)

        request_body = None
        self.logger.debug(f"test_list_channels url: {route.url}")
        result: requests.Response = self._successful_call(route.url, route.http_method, None,
            request_body, TEST_MASTER_BEARER_TOKEN)
        assert result.status_code == 200, result.reason

        response_body = result.json()
        # self.logger.debug(json.dumps(response_body, indent=4))

        assert isinstance(response_body, list)
        assert len(response_body) == 1
        for single_channel_data in response_body:
            assert single_channel_data['href'] == f"http://{TEST_HOST}:{TEST_PORT}/api/v1/channel/{CHANNEL_ID}"
            assert single_channel_data['public_read'] is True
            assert single_channel_data['public_write'] is True
            assert single_channel_data['sequenced'] is True
            assert single_channel_data['retention'] == {"min_age_days": 0, "max_age_days": 0,
                "auto_prune": True}
            assert isinstance(single_channel_data['access_tokens'], list)
            assert single_channel_data['access_tokens'][0]['id'] == 1
            issued_token_bytes = base64.urlsafe_b64decode(
                single_channel_data['access_tokens'][0]['token'])
            assert len(issued_token_bytes) == 64
            assert single_channel_data['access_tokens'][0]['token'] == CHANNEL_BEARER_TOKEN
            assert single_channel_data['access_tokens'][0]['description'] == "Owner"
            assert single_channel_data['access_tokens'][0]['can_read'] is True
            assert single_channel_data['access_tokens'][0]['can_write'] is True

    def test_get_single_channel_details(self):
        route = self.API_ROUTE_DEFS['get_single_channel_details']
        if route.auth_required:
            self._no_auth(route.url, route.http_method)
            self._wrong_auth_type(route.url, route.http_method)
            self._unauthorized(route.url, route.http_method)

        request_body = None
        url = route.url.format(channelid=CHANNEL_ID)
        self.logger.debug(f"test_get_single_channel_details url: {url}")
        result: requests.Response = self._successful_call(url, route.http_method, None,
            request_body, TEST_MASTER_BEARER_TOKEN)
        assert result.status_code == 200, result.reason

        response_body = result.json()
        # self.logger.debug(json.dumps(response_body, indent=4))

        single_channel_data = response_body
        assert single_channel_data['href'] == f"http://{TEST_HOST}:{TEST_PORT}/api/v1/channel/{CHANNEL_ID}"
        assert single_channel_data['public_read'] is True
        assert single_channel_data['public_write'] is True
        assert single_channel_data['sequenced'] is True
        assert single_channel_data['retention'] == {"min_age_days": 0, "max_age_days": 0, "auto_prune": True}
        assert isinstance(single_channel_data['access_tokens'], list)
        assert single_channel_data['access_tokens'][0]['id'] == 1
        issued_token_bytes = base64.urlsafe_b64decode(single_channel_data['access_tokens'][0]['token'])
        assert len(issued_token_bytes) == 64
        assert single_channel_data['access_tokens'][0]['description'] == "Owner"
        assert single_channel_data['access_tokens'][0]['can_read'] is True
        assert single_channel_data['access_tokens'][0]['can_write'] is True

    def test_update_single_channel_properties(self):
        route = self.API_ROUTE_DEFS['update_single_channel_properties']
        if route.auth_required:
            self._no_auth(route.url, route.http_method)
            self._wrong_auth_type(route.url, route.http_method)
            self._unauthorized(route.url, route.http_method)

        request_body = {
            "public_read": True,
            "public_write": True,
            "locked": False
        }
        url = route.url.format(channelid=CHANNEL_ID)
        self.logger.debug(f"test_update_single_channel_properties url: {url}")
        result: requests.Response = self._successful_call(url, route.http_method, None,
            request_body, TEST_MASTER_BEARER_TOKEN)
        assert result.status_code == 200, result.reason

        response_body = result.json()
        # self.logger.debug(json.dumps(response_body, indent=4))
        assert response_body == request_body

    def test_get_token_details(self):
        expected_response_body = {
            "id": 1,
            "token": CHANNEL_BEARER_TOKEN,
            "description": "Owner",
            "can_read": True,
            "can_write": True
        }

        route = self.API_ROUTE_DEFS['get_token_details']
        if route.auth_required:
            self._no_auth(route.url, route.http_method)
            self._wrong_auth_type(route.url, route.http_method)
            self._unauthorized(route.url, route.http_method)

        request_body = None
        url = route.url.format(channelid=CHANNEL_ID, tokenid=TOKEN_ID)
        self.logger.debug(f"test_get_token_details url: {url}")
        result: requests.Response = self._successful_call(url, route.http_method, None,
            request_body, TEST_MASTER_BEARER_TOKEN)

        assert result.status_code == 200, result.reason

        response_body = result.json()
        self.logger.debug(json.dumps(response_body, indent=4))
        assert response_body == expected_response_body

    def test_get_list_of_tokens(self):
        expected_response_body = [
            {
                "id": 1,
                "token": CHANNEL_BEARER_TOKEN,
                "description": "Owner",
                "can_read": True,
                "can_write": True
            }
        ]

        route = self.API_ROUTE_DEFS['get_list_of_tokens']
        if route.auth_required:
            self._no_auth(route.url, route.http_method)
            self._wrong_auth_type(route.url, route.http_method)
            self._unauthorized(route.url, route.http_method)

        request_body = None
        url = route.url.format(channelid=CHANNEL_ID, tokenid=TOKEN_ID)
        self.logger.debug(f"test_get_list_of_tokens url: {url}")
        result: requests.Response = self._successful_call(url, route.http_method, None,
            request_body, TEST_MASTER_BEARER_TOKEN)

        assert result.status_code == 200, result.reason

        response_body = result.json()
        self.logger.debug(json.dumps(response_body, indent=4))
        assert response_body == expected_response_body

    def test_create_new_token_for_channel(self):
        route = self.API_ROUTE_DEFS['create_new_token_for_channel']
        if route.auth_required:
            self._no_auth(route.url, route.http_method)
            self._wrong_auth_type(route.url, route.http_method)
            self._unauthorized(route.url, route.http_method)

        request_body = {
          "description": "some description",
          "can_read": True,
          "can_write": True
        }
        url = route.url.format(channelid=CHANNEL_ID)
        self.logger.debug(f"test_create_new_token_for_channel url: {url}")
        result: requests.Response = self._successful_call(url, route.http_method, None,
            request_body, TEST_MASTER_BEARER_TOKEN)

        assert result.status_code == 200, result.reason

        response_body = result.json()
        global CHANNEL_NEW_TOKEN
        CHANNEL_NEW_TOKEN = response_body['token']

        assert len(base64.urlsafe_b64decode(response_body['token'])) == 64
        expected_response_body = {
            "id": 2,
            "token": response_body['token'],
            "description": "some description",
            "can_read": True,
            "can_write": True
        }
        assert response_body == expected_response_body

    # MESSAGE MANAGEMENT APIS - USE CHANNEL-SPECIFIC BEARER TOKEN NOW

    def test_write_message_no_content_type_should_raise_400(self):
        route = self.API_ROUTE_DEFS['write_message']
        request_body = {"key": "value"}
        url = route.url.format(channelid=CHANNEL_ID)
        self.logger.debug(f"test_write_message_no_content_type_should_raise_400 url: {url}")
        result: requests.Response = self._successful_call(url, route.http_method, None,
            request_body, CHANNEL_BEARER_TOKEN)
        assert result.status_code == 400, result.reason
        assert result.reason is not None

    def test_write_message(self):
        """Uses CHANNEL_NEW_TOKEN to write messages for the CHANNEL_BEARER_TOKEN to read."""
        headers = {}
        headers["Content-Type"] = "application/json"
        request_body = {
            "key": "value"
        }

        route = self.API_ROUTE_DEFS['write_message']
        if route.auth_required:
            self._no_auth(route.url, route.http_method)
            self._wrong_auth_type(route.url, route.http_method)
            self._unauthorized(route.url, route.http_method, headers, request_body)

        url = route.url.format(channelid=CHANNEL_ID)
        self.logger.debug(f"test_write_message url: {url}")
        result: requests.Response = self._successful_call(url, route.http_method, headers,
            request_body, CHANNEL_NEW_TOKEN)

        assert result.status_code == 200, result.reason

        response_body = result.json()
        assert isinstance(response_body['sequence'], int)
        assert isinstance(datetime.datetime.fromisoformat(response_body['received']), datetime.datetime)
        assert response_body['content_type'] == 'application/json'
        assert response_body['payload'] == {'key': 'value'}

    def test_get_messages_head(self):
        route = self.API_ROUTE_DEFS['get_messages']
        if route.auth_required:
            self._no_auth(route.url, method='head')
            self._wrong_auth_type(route.url, method='head')
            self._unauthorized(route.url, method='head')

        url = route.url.format(channelid=CHANNEL_ID)
        self.logger.debug(f"test_get_messages_head url: {url}")
        result: requests.Response = self._successful_call(url, 'head', None, None,
            CHANNEL_BEARER_TOKEN)
        assert result.headers['ETag'] == "1"
        assert result.content == b''

    def test_get_messages_unread_should_get_one(self):
        route = self.API_ROUTE_DEFS['get_messages']
        if route.auth_required:
            self._no_auth(route.url, route.http_method)
            self._wrong_auth_type(route.url, route.http_method)
            self._unauthorized(route.url, route.http_method)

        query_params = "?unread=true"
        url = route.url.format(channelid=CHANNEL_ID) + query_params
        self.logger.debug(f"test_get_messages_head url: {url}")
        result: requests.Response = self._successful_call(url, route.http_method, None, None,
            CHANNEL_BEARER_TOKEN)
        assert result.headers['ETag'] == "1"
        response_body = result.json()
        assert isinstance(response_body, list)
        assert response_body[0]['sequence'] == 1
        assert isinstance(datetime.datetime.fromisoformat(response_body[0]['received']), datetime.datetime)
        assert response_body[0]['content_type'] == 'application/json'
        assert response_body[0]['payload'] == {'key': 'value'}

    def test_mark_message_read_or_unread(self):
        route = self.API_ROUTE_DEFS['mark_message_read_or_unread']
        if route.auth_required:
            self._no_auth(route.url, route.http_method)
            self._wrong_auth_type(route.url, route.http_method)
            self._unauthorized(route.url, route.http_method)

        body = {"read": True}
        sequence = 1
        query_params = "?older=true"
        url = route.url.format(channelid=CHANNEL_ID, sequence=sequence) + query_params
        result: requests.Response = self._successful_call(url, route.http_method, None, body,
            CHANNEL_BEARER_TOKEN)
        assert result.status_code == 200, result.reason

        sequence = 2
        url = route.url.format(channelid=CHANNEL_ID, sequence=sequence) + query_params
        result: requests.Response = self._successful_call(url, route.http_method, None, body,
            CHANNEL_BEARER_TOKEN)
        assert result.status_code == 404, result.reason
        assert result.reason is not None

    def test_delete_message(self):
        route = self.API_ROUTE_DEFS['delete_message']
        if route.auth_required:
            self._no_auth(route.url, route.http_method)
            self._wrong_auth_type(route.url, route.http_method)
            self._unauthorized(route.url, route.http_method)

        sequence = 1
        url = route.url.format(channelid=CHANNEL_ID, sequence=sequence)
        result: requests.Response = self._successful_call(url, route.http_method, None, None,
            CHANNEL_BEARER_TOKEN)
        assert result.status_code == 200, result.reason

        sequence = 2
        url = route.url.format(channelid=CHANNEL_ID, sequence=sequence)
        result: requests.Response = self._successful_call(url, route.http_method, None, None,
            CHANNEL_BEARER_TOKEN)
        assert result.status_code == 404, result.reason
        assert result.reason is not None

    # @pytest.mark.asyncio
    # def test_channels_websocket(self):
    #     EXPECTED_MSG_COUNT = 5
    #     self.logger.debug(f"CHANNEL_ID: {CHANNEL_ID}")
    #     self.logger.debug(f"CHANNEL_BEARER_TOKEN: {CHANNEL_BEARER_TOKEN}")
    #     self.logger.debug(f"CHANNEL_BEARER_TOKEN: {CHANNEL_NEW_TOKEN}")
    #
    #     async def wait_for_ws_message(completion_event: asyncio.Event):
    #         try:
    #             msg_received_count = 0
    #
    #             url = WS_URL_TEMPLATE_MSG_BOX.format(channelid=CHANNEL_ID)
    #             async with aiohttp.ClientSession() as session:
    #                 headers = {"Authorization": f"Bearer {CHANNEL_BEARER_TOKEN}"}
    #                 async with session.ws_connect(url, headers=headers, timeout=5.0) as ws:
    #                     self.logger.debug(f'Test websocket connected to {url}')
    #
    #                     async for msg in ws:
    #                         print('New message from msg box: ', msg.data)
    #                         msg: aiohttp.WSMessage
    #                         if msg.type == aiohttp.WSMsgType.TEXT:
    #                             content = json.loads(msg.data)
    #                             if content.get('error'):
    #                                 error: Error = Error.from_websocket_dict(content)
    #                                 self.logger.debug(f"Websocket error: {error}")
    #                                 if error.status == web.HTTPUnauthorized.status_code:
    #                                     raise web.HTTPUnauthorized()
    #
    #                             msg_received_count += 1
    #                             if msg_received_count == EXPECTED_MSG_COUNT:
    #                                 self.logger.debug(f"Websocket got all {msg_received_count} messages")
    #                                 completion_event.set()
    #                                 return
    #
    #                         if msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.ERROR,
    #                             aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSING):
    #                             self.logger.debug("CLOSED")
    #                             break
    #         except Exception as e:
    #             self.logger.exception("unexpected exception in wait_for_ws_message")
    #
    #     async def push_messages():
    #         for i in range(5):
    #             headers = {}
    #             headers["Content-Type"] = "application/json"
    #             request_body = {"key": "value"}
    #             route = self.API_ROUTE_DEFS['write_message']
    #             url = route.url.format(channelid=CHANNEL_ID)
    #             result: requests.Response = self._successful_call(url, route.http_method, headers,
    #                 request_body, CHANNEL_NEW_TOKEN)
    #             assert result.status_code == 200, result.reason
    #
    #     async def main():
    #         completion_event = asyncio.Event()
    #         asyncio.create_task(wait_for_ws_message(completion_event))
    #         await asyncio.sleep(2)
    #         await push_messages()
    #
    #         await completion_event.wait()
    #
    #     loop = asyncio.get_event_loop()
    #     loop.run_until_complete(main())

    def test_revoke_selected_token(self):
        route = self.API_ROUTE_DEFS['revoke_selected_token']
        if route.auth_required:
            self._no_auth(route.url, route.http_method)
            self._wrong_auth_type(route.url, route.http_method)
            self._unauthorized(route.url, route.http_method)

        good_bearer_token = TEST_MASTER_BEARER_TOKEN
        request_body = None
        url = route.url.format(channelid=CHANNEL_ID, tokenid=TOKEN_ID)
        # self.logger.debug(f"test_revoke_selected_token url: {url}")
        result: requests.Response = self._successful_call(url, route.http_method, None,
            request_body, good_bearer_token)

        assert result.status_code == web.HTTPNoContent.status_code

    def test_delete_channel(self):
        route = self.API_ROUTE_DEFS['delete_channel']
        if route.auth_required:
            self._no_auth(route.url, route.http_method)
            self._wrong_auth_type(route.url, route.http_method)
            self._unauthorized(route.url, route.http_method)

        good_bearer_token = TEST_MASTER_BEARER_TOKEN
        request_body = {
            "public_read": True,
            "public_write": True,
            "locked": False
        }
        url = route.url.format(channelid=CHANNEL_ID)
        self.logger.debug(f"test_delete_channel url: {url}")
        result: requests.Response = self._successful_call(url, route.http_method, None,
            request_body, good_bearer_token)

        assert result.status_code == web.HTTPNoContent.status_code
        sqlite_db: SQLiteDatabase = self.app['app_state'].sqlite_db
        sql = """SELECT * FROM msg_box"""
        rows = sqlite_db.execute(sql)
        assert len(rows) == 0

        sql = """SELECT * FROM msg_box_api_token"""
        rows = sqlite_db.execute(sql)
        assert len(rows) == 0

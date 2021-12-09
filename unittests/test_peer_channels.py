import asyncio

import aiohttp
from aiohttp import web
from aiohttp.web_app import Application
import base64
from bitcoinx import PrivateKey, PublicKey
import datetime
import json
import logging
import os
import sys
import threading
from pathlib import Path
import requests

from esv_reference_server.errors import Error
from esv_reference_server.sqlite_db import SQLiteDatabase
from server import logger, AiohttpServer, get_app
from unittests.conftest import _wrong_auth_type, _bad_token, _successful_call, _no_auth, \
    API_ROUTE_DEFS, app

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


class TestAiohttpRESTAPI:

    @classmethod
    def setup_class(self) -> None:
        self.logger = logging.getLogger("TestAiohttpRESTAPI")
        logging.basicConfig(format='%(asctime)s %(levelname)-8s %(name)-24s %(message)s',
            level=logging.DEBUG, datefmt='%Y-%m-%d %H:%M:%S')

    def setup_method(self) -> None:
        pass

    def teardown_method(self) -> None:
        pass

    @classmethod
    def teardown_class(self) -> None:
        pass

    async def _create_new_channel(self, API_ROUTE_DEFS):
        route = API_ROUTE_DEFS['create_new_channel']
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
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {TEST_MASTER_BEARER_TOKEN}"}
            async with session.post(route.url, headers=headers, json=request_body) as resp:
                self.logger.debug(f"resp.content = {resp.content}")
                assert resp.status == 200, resp.reason
                return await resp.json()

    async def _create_read_only_token(self, CHANNEL_ID, API_ROUTE_DEFS):
        route = API_ROUTE_DEFS['create_new_token_for_channel']
        request_body = {
            "description": "websocket read only token",
            "can_read": True,
            "can_write": False
        }
        url = route.url.format(channelid=CHANNEL_ID)
        self.logger.debug(f"test_create_new_token_for_channel url: {url}")
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {TEST_MASTER_BEARER_TOKEN}"}
            async with session.post(url, headers=headers, json=request_body) as resp:
                self.logger.debug(f"resp.content = {resp.content}")
                assert resp.status == 200, resp.reason
                return await resp.json()

    def test_ping(self):
        route = API_ROUTE_DEFS['ping']
        result = requests.get(route.url)
        assert result.text is not None

    def test_create_new_channel(self):
        route = API_ROUTE_DEFS['create_new_channel']
        if route.auth_required:
            _no_auth(route.url, route.http_method)
            _wrong_auth_type(route.url, route.http_method)
            _bad_token(route.url, route.http_method)

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
        result: requests.Response = _successful_call(route.url, route.http_method, None,
            request_body, TEST_MASTER_BEARER_TOKEN)

        assert result.status_code == 200, result.reason

        response_body = result.json()
        # self.logger.debug(json.dumps(response_body, indent=4))

        single_channel_data = response_body
        global CHANNEL_ID
        global CHANNEL_BEARER_TOKEN
        global CHANNEL_BEARER_TOKEN_ID
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
        CHANNEL_BEARER_TOKEN_ID = single_channel_data['access_tokens'][0]['id']
        assert single_channel_data['access_tokens'][0]['can_read'] is True
        assert single_channel_data['access_tokens'][0]['can_write'] is True

    def test_create_new_token_for_channel(self):
        route = API_ROUTE_DEFS['create_new_token_for_channel']
        if route.auth_required:
            _no_auth(route.url, route.http_method)
            _wrong_auth_type(route.url, route.http_method)
            _bad_token(route.url, route.http_method)

        request_body = {
          "description": "some description",
          "can_read": True,
          "can_write": False
        }
        url = route.url.format(channelid=CHANNEL_ID)
        self.logger.debug(f"test_create_new_token_for_channel url: {url}")
        result: requests.Response = _successful_call(url, route.http_method, None,
            request_body, TEST_MASTER_BEARER_TOKEN)

        assert result.status_code == 200, result.reason

        response_body = result.json()
        global CHANNEL_READ_ONLY_TOKEN
        global CHANNEL_READ_ONLY_TOKEN_ID
        CHANNEL_READ_ONLY_TOKEN_ID = response_body['id']
        CHANNEL_READ_ONLY_TOKEN = response_body['token']

        assert len(base64.urlsafe_b64decode(response_body['token'])) == 64
        expected_response_body = {
            "id": 2,
            "token": response_body['token'],
            "description": "some description",
            "can_read": True,
            "can_write": False
        }
        assert response_body == expected_response_body

    def test_list_channels(self):
        route = API_ROUTE_DEFS['list_channels']
        if route.auth_required:
            _no_auth(route.url, route.http_method)
            _wrong_auth_type(route.url, route.http_method)
            _bad_token(route.url, route.http_method)

        request_body = None
        self.logger.debug(f"test_list_channels url: {route.url}")
        result: requests.Response = _successful_call(route.url, route.http_method, None,
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
        route = API_ROUTE_DEFS['get_single_channel_details']
        if route.auth_required:
            _no_auth(route.url, route.http_method)
            _wrong_auth_type(route.url, route.http_method)
            _bad_token(route.url, route.http_method)

        request_body = None
        url = route.url.format(channelid=CHANNEL_ID)
        self.logger.debug(f"test_get_single_channel_details url: {url}")
        result: requests.Response = _successful_call(url, route.http_method, None,
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
        route = API_ROUTE_DEFS['update_single_channel_properties']
        if route.auth_required:
            _no_auth(route.url, route.http_method)
            _wrong_auth_type(route.url, route.http_method)
            _bad_token(route.url, route.http_method)

        request_body = {
            "public_read": True,
            "public_write": True,
            "locked": False
        }
        url = route.url.format(channelid=CHANNEL_ID)
        self.logger.debug(f"test_update_single_channel_properties url: {url}")
        result: requests.Response = _successful_call(url, route.http_method, None,
            request_body, TEST_MASTER_BEARER_TOKEN)
        assert result.status_code == 200, result.reason

        response_body = result.json()
        # self.logger.debug(json.dumps(response_body, indent=4))
        assert response_body == request_body

    def test_get_token_details(self):
        expected_response_body = {
            "id": CHANNEL_READ_ONLY_TOKEN_ID,
            "token": CHANNEL_READ_ONLY_TOKEN,
            "description": "some description",
            "can_read": True,
            "can_write": False
        }
        route = API_ROUTE_DEFS['get_token_details']
        if route.auth_required:
            _no_auth(route.url, route.http_method)
            _wrong_auth_type(route.url, route.http_method)
            _bad_token(route.url, route.http_method)

        request_body = None
        url = route.url.format(channelid=CHANNEL_ID, tokenid=CHANNEL_READ_ONLY_TOKEN_ID)
        self.logger.debug(f"test_get_token_details url: {url}")
        result: requests.Response = _successful_call(url, route.http_method, None,
            request_body, TEST_MASTER_BEARER_TOKEN)

        assert result.status_code == 200, result.reason

        response_body = result.json()
        self.logger.debug(json.dumps(response_body, indent=4))
        assert response_body == expected_response_body

    def test_get_list_of_tokens(self):
        expected_response_body = [
            {
                "id": CHANNEL_BEARER_TOKEN_ID,
                "token": CHANNEL_BEARER_TOKEN,
                "description": "Owner",
                "can_read": True,
                "can_write": True
            },
            {
                "id": CHANNEL_READ_ONLY_TOKEN_ID,
                "token": CHANNEL_READ_ONLY_TOKEN,
                "description": "some description",
                "can_read": True,
                "can_write": False
            }
        ]

        route = API_ROUTE_DEFS['get_list_of_tokens']
        if route.auth_required:
            _no_auth(route.url, route.http_method)
            _wrong_auth_type(route.url, route.http_method)
            _bad_token(route.url, route.http_method)

        request_body = None
        url = route.url.format(channelid=CHANNEL_ID, tokenid=CHANNEL_READ_ONLY_TOKEN_ID)
        self.logger.debug(f"test_get_list_of_tokens url: {url}")
        result: requests.Response = _successful_call(url, route.http_method, None,
            request_body, TEST_MASTER_BEARER_TOKEN)

        assert result.status_code == 200, result.reason

        response_body = result.json()
        self.logger.debug(json.dumps(response_body, indent=4))
        assert response_body == expected_response_body

    # MESSAGE MANAGEMENT APIS - USE CHANNEL-SPECIFIC BEARER TOKEN NOW

    def test_write_message_no_content_type_should_raise_400(self):
        route = API_ROUTE_DEFS['write_message']
        request_body = {"key": "value"}
        url = route.url.format(channelid=CHANNEL_ID)
        self.logger.debug(f"test_write_message_no_content_type_should_raise_400 url: {url}")
        result: requests.Response = _successful_call(url, route.http_method, None,
            request_body, CHANNEL_BEARER_TOKEN)
        assert result.status_code == 400, result.reason
        assert result.reason is not None

    def test_write_message_read_only_token_should_fail(self):
        headers = {}
        headers["Content-Type"] = "application/json"
        request_body = {
            "key": "value"
        }

        route = API_ROUTE_DEFS['write_message']
        if route.auth_required:
            _no_auth(route.url, route.http_method)
            _wrong_auth_type(route.url, route.http_method)
            _bad_token(route.url, route.http_method, headers, request_body)

        url = route.url.format(channelid=CHANNEL_ID)
        self.logger.debug(f"test_write_message_read_only_token_should_fail url: {url}")
        result: requests.Response = _successful_call(url, route.http_method, headers,
            request_body, CHANNEL_READ_ONLY_TOKEN)

        assert result.status_code == 401, result.reason

    def test_write_message(self):
        """Uses CHANNEL_BEARER_TOKEN to write messages for the CHANNEL_READ_ONLY_TOKEN to read."""
        headers = {}
        headers["Content-Type"] = "application/json"
        request_body = {
            "key": "value"
        }

        route = API_ROUTE_DEFS['write_message']
        if route.auth_required:
            _no_auth(route.url, route.http_method)
            _wrong_auth_type(route.url, route.http_method)
            _bad_token(route.url, route.http_method, headers, request_body)

        url = route.url.format(channelid=CHANNEL_ID)
        self.logger.debug(f"test_write_message url: {url}")
        result: requests.Response = _successful_call(url, route.http_method, headers,
            request_body, CHANNEL_BEARER_TOKEN)

        assert result.status_code == 200, result.reason

        response_body = result.json()
        assert isinstance(response_body['sequence'], int)
        assert isinstance(datetime.datetime.fromisoformat(response_body['received']), datetime.datetime)
        assert response_body['content_type'] == 'application/json'
        assert response_body['payload'] == {'key': 'value'}

    def test_get_messages_head(self):
        route = API_ROUTE_DEFS['get_messages']
        if route.auth_required:
            _no_auth(route.url, method='head')
            _wrong_auth_type(route.url, method='head')
            _bad_token(route.url, method='head')

        url = route.url.format(channelid=CHANNEL_ID)
        self.logger.debug(f"test_get_messages_head url: {url}")
        result: requests.Response = _successful_call(url, 'head', None, None,
            CHANNEL_READ_ONLY_TOKEN)
        assert result.headers['ETag'] == "1"
        assert result.content == b''

    def test_get_messages_unread_should_get_one(self):
        route = API_ROUTE_DEFS['get_messages']
        if route.auth_required:
            _no_auth(route.url, route.http_method)
            _wrong_auth_type(route.url, route.http_method)
            _bad_token(route.url, route.http_method)

        query_params = "?unread=true"
        url = route.url.format(channelid=CHANNEL_ID) + query_params
        self.logger.debug(f"test_get_messages_head url: {url}")
        result: requests.Response = _successful_call(url, route.http_method, None, None,
            CHANNEL_READ_ONLY_TOKEN)
        assert result.headers['ETag'] == "1"
        response_body = result.json()
        assert isinstance(response_body, list)
        assert response_body[0]['sequence'] == 1
        assert isinstance(datetime.datetime.fromisoformat(response_body[0]['received']), datetime.datetime)
        assert response_body[0]['content_type'] == 'application/json'
        assert response_body[0]['payload'] == {'key': 'value'}

    def test_mark_message_read_or_unread(self):
        route = API_ROUTE_DEFS['mark_message_read_or_unread']
        if route.auth_required:
            _no_auth(route.url, route.http_method)
            _wrong_auth_type(route.url, route.http_method)
            _bad_token(route.url, route.http_method)

        body = {"read": True}
        sequence = 1
        query_params = "?older=true"
        url = route.url.format(channelid=CHANNEL_ID, sequence=sequence) + query_params
        result: requests.Response = _successful_call(url, route.http_method, None, body,
            CHANNEL_READ_ONLY_TOKEN)
        assert result.status_code == 200, result.reason

        sequence = 2
        url = route.url.format(channelid=CHANNEL_ID, sequence=sequence) + query_params
        result: requests.Response = _successful_call(url, route.http_method, None, body,
            CHANNEL_READ_ONLY_TOKEN)
        assert result.status_code == 404, result.reason
        assert result.reason is not None

    def test_delete_message_read_only_token_should_fail(self):
        route = API_ROUTE_DEFS['delete_message']
        if route.auth_required:
            _no_auth(route.url, route.http_method)
            _wrong_auth_type(route.url, route.http_method)
            _bad_token(route.url, route.http_method)

        sequence = 1
        url = route.url.format(channelid=CHANNEL_ID, sequence=sequence)
        result: requests.Response = _successful_call(url, route.http_method, None, None,
            CHANNEL_READ_ONLY_TOKEN)
        assert result.status_code == 401, result.reason

        sequence = 2
        url = route.url.format(channelid=CHANNEL_ID, sequence=sequence)
        result: requests.Response = _successful_call(url, route.http_method, None, None,
            CHANNEL_READ_ONLY_TOKEN)
        assert result.status_code == 401, result.reason
        assert result.reason is not None

    def test_delete_message_should_succeed(self):
        route = API_ROUTE_DEFS['delete_message']
        if route.auth_required:
            _no_auth(route.url, route.http_method)
            _wrong_auth_type(route.url, route.http_method)
            _bad_token(route.url, route.http_method)

        sequence = 1
        url = route.url.format(channelid=CHANNEL_ID, sequence=sequence)
        result: requests.Response = _successful_call(url, route.http_method, None, None,
            CHANNEL_BEARER_TOKEN)
        assert result.status_code == 200, result.reason

        sequence = 2
        url = route.url.format(channelid=CHANNEL_ID, sequence=sequence)
        result: requests.Response = _successful_call(url, route.http_method, None, None,
            CHANNEL_BEARER_TOKEN)
        assert result.status_code == 404, result.reason
        assert result.reason is not None

    def test_channels_websocket(self):
        logger = logging.getLogger("websocket-test")
        async def wait_on_sub(url: str, msg_box_api_token: str, expected_count: int, completion_event: asyncio.Event):
            await subscribe_to_msg_box_notifications(url, msg_box_api_token, expected_count, completion_event)

        async def subscribe_to_msg_box_notifications(url: str, msg_box_api_token: str,
                expected_count: int, completion_event: asyncio.Event) -> None:

            count = 0
            async with aiohttp.ClientSession() as session:
                headers = {"Authorization": f"Bearer {msg_box_api_token}"}
                async with session.ws_connect(url, headers=headers, timeout=5.0) as ws:
                    self.logger.info(f'Connected to {url}')
                    async for msg in ws:
                        msg: aiohttp.WSMessage
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            content = json.loads(msg.data)
                            self.logger.info(f'New message from msg box: {content}')

                            if isinstance(content, dict) and content.get('error'):
                                error: Error = Error.from_websocket_dict(content)
                                self.logger.info(f"Websocket error: {error}")
                                if error.status == web.HTTPUnauthorized.status_code:
                                    raise web.HTTPUnauthorized()

                            count += 1
                            if expected_count == count:
                                self.logger.debug(f"Received all {expected_count} messages")
                                await session.close()
                                completion_event.set()
                                return

                        if msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.ERROR,
                                        aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSING):
                            self.logger.info("CLOSED")
                            break

        async def push_messages(CHANNEL_ID, CHANNEL_BEARER_TOKEN, expected_msg_count: int):
            for i in range(expected_msg_count):
                headers = {}
                headers["Content-Type"] = "application/json"
                headers["Authorization"] = f"Bearer {CHANNEL_BEARER_TOKEN}"
                request_body = {"key": "value"}

                url = f"http://127.0.0.1:{TEST_PORT}/api/v1/channel/{CHANNEL_ID}"

                async with aiohttp.ClientSession() as session:
                    headers = {"Authorization": f"Bearer {CHANNEL_BEARER_TOKEN}"}
                    async with session.post(url, headers=headers, json=request_body) as resp:
                        self.logger.debug(f"push_messages = {await resp.json()}")
                        assert resp.status == 200, resp.reason

        async def main():
            EXPECTED_MSG_COUNT = 10
            logger.debug(f"CHANNEL_ID: {CHANNEL_ID}")
            logger.debug(f"CHANNEL_BEARER_TOKEN: {CHANNEL_BEARER_TOKEN}")
            logger.debug(f"CHANNEL_READ_ONLY_TOKEN: {CHANNEL_READ_ONLY_TOKEN}")

            completion_event = asyncio.Event()
            url = WS_URL_TEMPLATE_MSG_BOX.format(channelid=CHANNEL_ID)
            asyncio.create_task(wait_on_sub(url, CHANNEL_BEARER_TOKEN, EXPECTED_MSG_COUNT, completion_event))
            await asyncio.sleep(3)
            await push_messages(CHANNEL_ID, CHANNEL_BEARER_TOKEN, EXPECTED_MSG_COUNT)
            await completion_event.wait()

        asyncio.run(main())

    def test_revoke_selected_token(self):
        route = API_ROUTE_DEFS['revoke_selected_token']
        if route.auth_required:
            _no_auth(route.url, route.http_method)
            _wrong_auth_type(route.url, route.http_method)
            _bad_token(route.url, route.http_method)

        good_bearer_token = TEST_MASTER_BEARER_TOKEN
        request_body = None
        url = route.url.format(channelid=CHANNEL_ID, tokenid=CHANNEL_READ_ONLY_TOKEN_ID)
        self.logger.debug(f"test_revoke_selected_token url: {url}")
        result: requests.Response = _successful_call(url, route.http_method, None,
            request_body, good_bearer_token)

        assert result.status_code == web.HTTPNoContent.status_code

    def test_expired_token_should_fail(self):
        route = API_ROUTE_DEFS['get_token_details']
        if route.auth_required:
            _no_auth(route.url, route.http_method)
            _wrong_auth_type(route.url, route.http_method)
            _bad_token(route.url, route.http_method)

        expired_bearer_token = CHANNEL_READ_ONLY_TOKEN
        request_body = None
        url = route.url.format(channelid=CHANNEL_ID, tokenid=CHANNEL_READ_ONLY_TOKEN_ID)
        self.logger.debug(f"test_revoke_selected_token url: {url}")
        result: requests.Response = _successful_call(url, route.http_method, None,
            request_body, expired_bearer_token)

        assert result.status_code == 401

    def test_delete_channel(self):
        route = API_ROUTE_DEFS['delete_channel']
        if route.auth_required:
            _no_auth(route.url, route.http_method)
            _wrong_auth_type(route.url, route.http_method)
            _bad_token(route.url, route.http_method)

        good_bearer_token = TEST_MASTER_BEARER_TOKEN
        request_body = {
            "public_read": True,
            "public_write": True,
            "locked": False
        }
        url = route.url.format(channelid=CHANNEL_ID)
        self.logger.debug(f"test_delete_channel url: {url}")
        result: requests.Response = _successful_call(url, route.http_method, None,
            request_body, good_bearer_token)

        assert result.status_code == web.HTTPNoContent.status_code
        sqlite_db: SQLiteDatabase = app['app_state'].sqlite_db
        sql = """SELECT * FROM msg_box"""
        rows = sqlite_db.execute(sql)
        assert len(rows) == 0

        sql = """SELECT * FROM msg_box_api_token"""
        rows = sqlite_db.execute(sql)
        assert len(rows) == 0

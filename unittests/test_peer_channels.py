import asyncio
import aiohttp
import pytest
from aiohttp import web, WSServerHandshakeError
import base64
from bitcoinx import PrivateKey, PublicKey
import datetime
import json
import logging
import os
from pathlib import Path
import requests

from esv_reference_server.errors import WebsocketUnauthorizedException
from esv_reference_server.sqlite_db import SQLiteDatabase
from unittests._endpoint_map import ENDPOINT_MAP
from unittests.conftest import _wrong_auth_type, _bad_token, _successful_call, _no_auth, \
    WS_URL_GENERAL, _subscribe_to_general_notifications_peer_channels

TEST_HOST = "127.0.0.1"
TEST_PORT = 52462
WS_URL_TEMPLATE_MSG_BOX = "ws://localhost:52462/api/v1/channel/{channelid}/notify"

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


class TestAiohttpRESTAPI:

    logger = logging.getLogger("test-aiohttp-rest-api")

    @classmethod
    def setup_class(self) -> None:
        logging.basicConfig(format='%(asctime)s %(levelname)-8s %(name)-24s %(message)s',
            level=logging.DEBUG, datefmt='%Y-%m-%d %H:%M:%S')

    def setup_method(self) -> None:
        pass

    def teardown_method(self) -> None:
        pass

    @classmethod
    def teardown_class(self) -> None:
        pass

    async def _create_new_channel(self):
        route = ENDPOINT_MAP['create_new_channel']
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
                single_channel_data = await resp.json()
                CHANNEL_ID = single_channel_data['id']
                CHANNEL_BEARER_TOKEN = single_channel_data['access_tokens'][0]['token']
                CHANNEL_BEARER_TOKEN_ID = single_channel_data['access_tokens'][0]['id']
                return CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID

    async def _create_read_only_token(self, CHANNEL_ID):
        route = ENDPOINT_MAP['create_new_token_for_channel']
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
                response_body = await resp.json()
                CHANNEL_READ_ONLY_TOKEN_ID = response_body['id']
                CHANNEL_READ_ONLY_TOKEN = response_body['token']
                return CHANNEL_READ_ONLY_TOKEN_ID, CHANNEL_READ_ONLY_TOKEN

    @pytest.mark.asyncio
    def test_ping(self):
        route = ENDPOINT_MAP['ping']
        result = requests.get(route.url)
        assert result.text is not None

    @pytest.mark.asyncio
    def test_create_new_channel(self):
        route = ENDPOINT_MAP['create_new_channel']
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
        assert single_channel_data['access_tokens'][0]['can_read'] is True
        assert single_channel_data['access_tokens'][0]['can_write'] is True

    @pytest.mark.asyncio
    async def test_create_new_token_for_channel(self):
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()

        route = ENDPOINT_MAP['create_new_token_for_channel']
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

        assert len(base64.urlsafe_b64decode(response_body['token'])) == 64
        expected_response_body = {
            "id": 3,
            "token": response_body['token'],
            "description": "some description",
            "can_read": True,
            "can_write": False
        }
        assert response_body == expected_response_body

    @pytest.mark.asyncio
    def test_list_channels(self):
        route = ENDPOINT_MAP['list_channels']
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
        assert len(response_body) == 2
        for single_channel_data in response_body:
            # assert single_channel_data['href'] == f"http://{TEST_HOST}:{TEST_PORT}/api/v1/channel/{CHANNEL_ID}"
            assert single_channel_data['public_read'] is True
            assert single_channel_data['public_write'] is True
            assert single_channel_data['sequenced'] is True
            assert single_channel_data['retention'] == {"min_age_days": 0, "max_age_days": 0,
                "auto_prune": True}
            assert isinstance(single_channel_data['access_tokens'], list)
            assert isinstance(single_channel_data['access_tokens'][0]['id'], int)
            issued_token_bytes = base64.urlsafe_b64decode(
                single_channel_data['access_tokens'][0]['token'])
            assert len(issued_token_bytes) == 64
            # assert single_channel_data['access_tokens'][0]['token'] == CHANNEL_BEARER_TOKEN
            assert single_channel_data['access_tokens'][0]['description'] == "Owner"
            assert single_channel_data['access_tokens'][0]['can_read'] is True
            assert single_channel_data['access_tokens'][0]['can_write'] is True

    @pytest.mark.asyncio
    async def test_get_single_channel_details(self):
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()

        route = ENDPOINT_MAP['get_single_channel_details']
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
        assert isinstance(single_channel_data['access_tokens'][0]['id'], int)
        issued_token_bytes = base64.urlsafe_b64decode(single_channel_data['access_tokens'][0]['token'])
        assert len(issued_token_bytes) == 64
        assert single_channel_data['access_tokens'][0]['description'] == "Owner"
        assert single_channel_data['access_tokens'][0]['can_read'] is True
        assert single_channel_data['access_tokens'][0]['can_write'] is True

    @pytest.mark.asyncio
    async def test_update_single_channel_properties(self):
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()

        route = ENDPOINT_MAP['update_single_channel_properties']
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

    @pytest.mark.asyncio
    async def test_get_token_details(self):
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()
        CHANNEL_READ_ONLY_TOKEN_ID, CHANNEL_READ_ONLY_TOKEN = \
            await self._create_read_only_token(CHANNEL_ID)

        expected_response_body = {
            "id": CHANNEL_READ_ONLY_TOKEN_ID,
            "token": CHANNEL_READ_ONLY_TOKEN,
            "description": "websocket read only token",
            "can_read": True,
            "can_write": False
        }
        route = ENDPOINT_MAP['get_token_details']
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

    @pytest.mark.asyncio
    async def test_get_list_of_tokens(self):
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()
        CHANNEL_READ_ONLY_TOKEN_ID, CHANNEL_READ_ONLY_TOKEN = \
            await self._create_read_only_token(CHANNEL_ID)

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
                "description": "websocket read only token",
                "can_read": True,
                "can_write": False
            }
        ]

        route = ENDPOINT_MAP['get_list_of_tokens']
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

    @pytest.mark.asyncio
    async def test_write_message_no_content_type_should_raise_400(self):
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()

        route = ENDPOINT_MAP['write_message']
        request_body = {"key": "value"}
        url = route.url.format(channelid=CHANNEL_ID)
        self.logger.debug(f"test_write_message_no_content_type_should_raise_400 url: {url}")
        result: requests.Response = _successful_call(url, route.http_method, None,
            request_body, CHANNEL_BEARER_TOKEN)
        assert result.status_code == 400, result.reason
        assert result.reason is not None

    @pytest.mark.asyncio
    async def test_write_message_read_only_token_should_fail(self):
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()
        CHANNEL_READ_ONLY_TOKEN_ID, CHANNEL_READ_ONLY_TOKEN = \
            await self._create_read_only_token(CHANNEL_ID)

        headers = {}
        headers["Content-Type"] = "application/json"
        request_body = {
            "key": "value"
        }

        route = ENDPOINT_MAP['write_message']
        if route.auth_required:
            _no_auth(route.url, route.http_method)
            _wrong_auth_type(route.url, route.http_method)
            _bad_token(route.url, route.http_method, headers, request_body)

        url = route.url.format(channelid=CHANNEL_ID)
        self.logger.debug(f"test_write_message_read_only_token_should_fail url: {url}")
        result: requests.Response = _successful_call(url, route.http_method, headers,
            request_body, CHANNEL_READ_ONLY_TOKEN)

        assert result.status_code == 401, result.reason

    def _write_message(self, CHANNEL_ID, CHANNEL_BEARER_TOKEN):
        headers = {}
        headers["Content-Type"] = "application/json"
        request_body = {
            "key": "value"
        }
        route = ENDPOINT_MAP['write_message']
        url = route.url.format(channelid=CHANNEL_ID)
        self.logger.debug(f"test_write_message url: {url}")
        result: requests.Response = _successful_call(url, route.http_method, headers,
            request_body, CHANNEL_BEARER_TOKEN)
        assert result.status_code == 200, result.reason
        return result

    @pytest.mark.asyncio
    async def test_write_message(self):
        """Uses CHANNEL_BEARER_TOKEN to write messages for the CHANNEL_READ_ONLY_TOKEN to read."""
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()

        headers = {}
        headers["Content-Type"] = "application/json"
        request_body = {
            "key": "value"
        }
        route = ENDPOINT_MAP['write_message']
        url = route.url.format(channelid=CHANNEL_ID)
        if route.auth_required:
            _no_auth(url, route.http_method)
            _wrong_auth_type(url, route.http_method)
            _bad_token(url, route.http_method, headers, request_body)

        self.logger.debug(f"test_write_message url: {url}")
        result: requests.Response = _successful_call(url, route.http_method, headers,
            request_body, CHANNEL_BEARER_TOKEN)

        assert result.status_code == 200, result.reason

        response_body = result.json()
        assert isinstance(response_body['sequence'], int)
        assert isinstance(datetime.datetime.fromisoformat(response_body['received']), datetime.datetime)
        assert response_body['content_type'] == 'application/json'
        assert response_body['payload'] == {'key': 'value'}

    @pytest.mark.asyncio
    async def test_get_messages_head(self):
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()
        CHANNEL_READ_ONLY_TOKEN_ID, CHANNEL_READ_ONLY_TOKEN = \
            await self._create_read_only_token(CHANNEL_ID)
        self._write_message(CHANNEL_ID, CHANNEL_BEARER_TOKEN)

        route = ENDPOINT_MAP['get_messages']
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

    @pytest.mark.asyncio
    async def test_get_messages_unread_should_get_one(self):
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()
        CHANNEL_READ_ONLY_TOKEN_ID, CHANNEL_READ_ONLY_TOKEN = \
            await self._create_read_only_token(CHANNEL_ID)
        _response = self._write_message(CHANNEL_ID, CHANNEL_BEARER_TOKEN)

        route = ENDPOINT_MAP['get_messages']
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

    @pytest.mark.asyncio
    async def test_mark_message_read_or_unread(self):
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()
        CHANNEL_READ_ONLY_TOKEN_ID, CHANNEL_READ_ONLY_TOKEN = \
            await self._create_read_only_token(CHANNEL_ID)
        _response = self._write_message(CHANNEL_ID, CHANNEL_BEARER_TOKEN)

        route = ENDPOINT_MAP['mark_message_read_or_unread']
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

    @pytest.mark.asyncio
    async def test_delete_message_read_only_token_should_fail(self):
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()
        CHANNEL_READ_ONLY_TOKEN_ID, CHANNEL_READ_ONLY_TOKEN = \
            await self._create_read_only_token(CHANNEL_ID)
        _response = self._write_message(CHANNEL_ID, CHANNEL_BEARER_TOKEN)

        route = ENDPOINT_MAP['delete_message']
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

    @pytest.mark.asyncio
    async def test_delete_message_should_succeed(self):
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()
        _response = self._write_message(CHANNEL_ID, CHANNEL_BEARER_TOKEN)

        route = ENDPOINT_MAP['delete_message']
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

    async def _subscribe_to_msg_box_notifications(self, url: str, msg_box_api_token: str,
            expected_count: int, completion_event: asyncio.Event) -> None:

        count = 0
        async with aiohttp.ClientSession() as session:
            try:
                async with session.ws_connect(url + f"?token={msg_box_api_token}", timeout=5.0) as ws:

                    self.logger.info(f'Connected to {url}')
                    async for msg in ws:
                        msg: aiohttp.WSMessage
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            content = json.loads(msg.data)
                            self.logger.info(f'New message from msg box: {content}')

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
            except WSServerHandshakeError as e:
                if e.status == 401:
                    raise WebsocketUnauthorizedException()

    @pytest.mark.asyncio
    def test_channels_websocket_bad_auth_should_fail(self):
        async def wait_on_sub(url: str, msg_box_api_token: str, expected_count: int, completion_event: asyncio.Event):
            try:
                await self._subscribe_to_msg_box_notifications(url, msg_box_api_token, expected_count, completion_event)
            except WebsocketUnauthorizedException:
                self.logger.debug(f"Websocket unauthorized - bad token")
                assert True  # Auth should failed

        completion_event = asyncio.Event()
        url = WS_URL_TEMPLATE_MSG_BOX.format(channelid=CHANNEL_ID)
        asyncio.run(wait_on_sub(url, "BAD_BEARER_TOKEN", 0, completion_event))

    @pytest.mark.asyncio
    def test_channels_websocket(self):
        logger = logging.getLogger("websocket-test")
        async def wait_on_sub(url: str, msg_box_api_token: str, expected_count: int, completion_event: asyncio.Event):
            try:
                await self._subscribe_to_msg_box_notifications(url, msg_box_api_token, expected_count, completion_event)
            except WebsocketUnauthorizedException:
                self.logger.debug(f"Auth failed")
                assert False  # Auth should have passed

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
            CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()
            CHANNEL_READ_ONLY_TOKEN_ID, CHANNEL_READ_ONLY_TOKEN = \
                await self._create_read_only_token(CHANNEL_ID)

            EXPECTED_MSG_COUNT = 10
            logger.debug(f"CHANNEL_ID: {CHANNEL_ID}")
            logger.debug(f"CHANNEL_BEARER_TOKEN: {CHANNEL_BEARER_TOKEN}")
            logger.debug(f"CHANNEL_READ_ONLY_TOKEN: {CHANNEL_READ_ONLY_TOKEN}")

            completion_event = asyncio.Event()
            url = WS_URL_TEMPLATE_MSG_BOX.format(channelid=CHANNEL_ID)
            task1 = asyncio.create_task(wait_on_sub(url, CHANNEL_BEARER_TOKEN, EXPECTED_MSG_COUNT, completion_event))
            await asyncio.sleep(3)
            task2 = asyncio.create_task(push_messages(CHANNEL_ID, CHANNEL_BEARER_TOKEN, EXPECTED_MSG_COUNT))
            await asyncio.gather(task1, task2)
            await completion_event.wait()

        asyncio.run(main())

    @pytest.mark.asyncio
    def test_general_purpose_websocket_bad_auth_should_fail(self):
        async def wait_on_sub(url: str, api_token: str,
                              expected_count: int, completion_event: asyncio.Event):
            try:
                await _subscribe_to_general_notifications_peer_channels(url,
                    api_token, expected_count, completion_event)
            except WebsocketUnauthorizedException:
                self.logger.debug(f"Websocket unauthorized - bad token")
                assert True  # Auth should failed

        completion_event = asyncio.Event()
        url = WS_URL_GENERAL
        asyncio.run(wait_on_sub(url, "BAD_BEARER_TOKEN", 0, completion_event))

    @pytest.mark.asyncio
    def test_general_purpose_websocket_peer_channel_notifications(self):
        logger = logging.getLogger("websocket-test")
        async def wait_on_sub(url: str, api_token: str, expected_count: int,
                completion_event: asyncio.Event):
            try:
                await _subscribe_to_general_notifications_peer_channels(
                    url, api_token, expected_count, completion_event)
            except WebsocketUnauthorizedException:
                self.logger.debug(f"Auth failed")
                assert False  # Auth should have passed

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
            CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()
            CHANNEL_READ_ONLY_TOKEN_ID, CHANNEL_READ_ONLY_TOKEN = \
                await self._create_read_only_token(CHANNEL_ID)

            EXPECTED_MSG_COUNT = 10
            logger.debug(f"CHANNEL_ID: {CHANNEL_ID}")
            logger.debug(f"CHANNEL_BEARER_TOKEN: {CHANNEL_BEARER_TOKEN}")
            logger.debug(f"CHANNEL_READ_ONLY_TOKEN: {CHANNEL_READ_ONLY_TOKEN}")

            completion_event = asyncio.Event()
            url = WS_URL_GENERAL
            task1 = asyncio.create_task(wait_on_sub(url, TEST_MASTER_BEARER_TOKEN, EXPECTED_MSG_COUNT,
                completion_event))
            await asyncio.sleep(3)
            task2 = asyncio.create_task(push_messages(CHANNEL_ID, CHANNEL_BEARER_TOKEN,
                EXPECTED_MSG_COUNT))
            await asyncio.gather(task1, task2)
            await completion_event.wait()

        asyncio.run(main())

    @pytest.mark.asyncio
    async def test_revoke_selected_token(self):
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()
        CHANNEL_READ_ONLY_TOKEN_ID, CHANNEL_READ_ONLY_TOKEN = \
            await self._create_read_only_token(CHANNEL_ID)

        route = ENDPOINT_MAP['revoke_selected_token']
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

    def _revoke_token(self, CHANNEL_ID, CHANNEL_READ_ONLY_TOKEN_ID):
        route = ENDPOINT_MAP['revoke_selected_token']
        good_bearer_token = TEST_MASTER_BEARER_TOKEN
        request_body = None
        url = route.url.format(channelid=CHANNEL_ID, tokenid=CHANNEL_READ_ONLY_TOKEN_ID)
        self.logger.debug(f"test_revoke_selected_token url: {url}")
        result: requests.Response = _successful_call(url, route.http_method, None,
            request_body, good_bearer_token)
        return result

    @pytest.mark.asyncio
    async def test_expired_token_should_fail(self):
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()
        CHANNEL_READ_ONLY_TOKEN_ID, CHANNEL_READ_ONLY_TOKEN = \
            await self._create_read_only_token(CHANNEL_ID)
        self._revoke_token(CHANNEL_ID, CHANNEL_READ_ONLY_TOKEN_ID)

        route = ENDPOINT_MAP['get_token_details']
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

    @pytest.mark.asyncio
    async def test_delete_channel(self):
        _CHANNEL_ID, _CHANNEL_BEARER_TOKEN, _CHANNEL_BEARER_TOKEN_ID = \
            await self._create_new_channel()

        datastore_location = Path(os.environ['DATASTORE_LOCATION'])
        sqlite_db: SQLiteDatabase = SQLiteDatabase(datastore_location)
        sql = """SELECT * FROM msg_box"""
        rows = sqlite_db.execute(sql)
        assert len(rows) > 0

        channel_ids_for_deletion = []
        for row in rows:
            id, account_id, externalid, publicread, publicwrite, locked, sequenced, \
                minagedays, maxagedays, autoprune = row
            channel_ids_for_deletion.append(externalid)

        route = ENDPOINT_MAP['delete_channel']
        if route.auth_required:
            _no_auth(route.url, route.http_method)
            _wrong_auth_type(route.url, route.http_method)
            _bad_token(route.url, route.http_method)

        good_bearer_token = TEST_MASTER_BEARER_TOKEN
        for channel_id in channel_ids_for_deletion:
            url = route.url.format(channelid=channel_id)
            self.logger.debug(f"test_delete_channel url: {url}")
            result: requests.Response = _successful_call(url, route.http_method, None,
                None, good_bearer_token)
            assert result.status_code == web.HTTPNoContent.status_code

        sql = """SELECT * FROM msg_box"""
        rows = sqlite_db.execute(sql)
        assert len(rows) == 0

        sql = """SELECT * FROM msg_box_api_token"""
        rows = sqlite_db.execute(sql)
        assert len(rows) == 0

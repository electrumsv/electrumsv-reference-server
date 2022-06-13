from __future__ import annotations
import asyncio
import base64
from datetime import datetime
from http import HTTPStatus
import json
import logging
import os
from pathlib import Path

from esv_reference_server.utils import from_isoformat

try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.10.0 builds and bundled version of 3.35.5.
    import sqlite3  # type: ignore

import aiohttp
from aiohttp import web, WSServerHandshakeError
from bitcoinx import PrivateKey, PublicKey
from electrumsv_database.sqlite import replace_db_context_with_connection
import pytest
import requests

from esv_reference_server.application_state import ApplicationState
from esv_reference_server.errors import WebsocketUnauthorizedException
from esv_reference_server import sqlite_db

from .conftest import _wrong_auth_type, _bad_token, _successful_call, _no_auth, \
    _subscribe_to_general_notifications_peer_channels, TEST_EXTERNAL_HOST, TEST_EXTERNAL_PORT, \
    WS_URL_GENERAL


WS_URL_TEMPLATE_MSG_BOX = "ws://"+ TEST_EXTERNAL_HOST +":"+ str(TEST_EXTERNAL_PORT) + \
    "/api/v1/channel/{channelid}/notify"

PRIVATE_KEY_1 = PrivateKey.from_hex(
    "720f1987db69efa562b3dabd78e51f19bd8da76c70ad839b72b939f4071b144b")
PUBLIC_KEY_1: PublicKey = PRIVATE_KEY_1.public_key

REF_TYPE_OUTPUT = 0
REF_TYPE_INPUT = 1
STREAM_TERMINATION_BYTE = b"\x00"

MODULE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))

CHANNEL_ID: str = ""
CHANNEL_BEARER_TOKEN: str = ""
CHANNEL_BEARER_TOKEN_ID: int = 0
CHANNEL_READ_ONLY_TOKEN: str = ""
CHANNEL_READ_ONLY_TOKEN_ID: int = 0


class TestAiohttpRESTAPI:

    logger = logging.getLogger("test-aiohttp-rest-api")
    _account_id: int
    _api_key: str

    @classmethod
    def setup_class(cls) -> None:
        assert ApplicationState.singleton_reference is not None
        application_state = ApplicationState.singleton_reference()
        assert application_state is not None

        cls._account_id, cls._api_key = application_state.database_context.run_in_thread(
            sqlite_db.create_account, PUBLIC_KEY_1.to_bytes(compressed=True))

    def setup_method(self) -> None:
        pass

    def teardown_method(self) -> None:
        pass

    @classmethod
    def teardown_class(cls) -> None:
        pass

    async def _create_new_channel(self) -> tuple[str, str, str]:
        URL = "http://{host}:{port}/api/v1/channel/manage".format(host=TEST_EXTERNAL_HOST,
            port=TEST_EXTERNAL_PORT)
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

        self.logger.debug("test_create_new_channel url: %s", URL)
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {self._api_key}"}
            async with session.post(URL, headers=headers, json=request_body) as resp:
                self.logger.debug("resp.content = %s", resp.content)
                assert resp.status == 200, resp.reason
                single_channel_data = await resp.json()
                CHANNEL_ID = single_channel_data['id']
                CHANNEL_BEARER_TOKEN = single_channel_data['access_tokens'][0]['token']
                CHANNEL_BEARER_TOKEN_ID = single_channel_data['access_tokens'][0]['id']
                return CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID

    async def _create_read_only_token(self, CHANNEL_ID: str) -> tuple[str, str]:
        URL = "http://"+ TEST_EXTERNAL_HOST +":"+ str(TEST_EXTERNAL_PORT) + \
            "/api/v1/channel/manage/{channelid}/api-token"
        request_body = {
            "description": "websocket read only token",
            "can_read": True,
            "can_write": False
        }
        url = URL.format(channelid=CHANNEL_ID)
        self.logger.debug("test_create_new_token_for_channel url: %s", url)
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {self._api_key}"}
            async with session.post(url, headers=headers, json=request_body) as resp:
                self.logger.debug("resp.content = %s", resp.content)
                assert resp.status == 200, resp.reason
                response_body = await resp.json()
                CHANNEL_READ_ONLY_TOKEN_ID = response_body['id']
                CHANNEL_READ_ONLY_TOKEN = response_body['token']
                return CHANNEL_READ_ONLY_TOKEN_ID, CHANNEL_READ_ONLY_TOKEN

    @pytest.mark.asyncio
    def test_ping(self) -> None:
        URL = "http://{host}:{port}/".format(host=TEST_EXTERNAL_HOST, port=TEST_EXTERNAL_PORT)
        result = requests.get(URL)
        assert result.text is not None

    @pytest.mark.asyncio
    def test_create_new_channel(self) -> None:
        URL = 'http://{host}:{port}/api/v1/channel/manage'.format(host=TEST_EXTERNAL_HOST,
            port=TEST_EXTERNAL_PORT)
        HTTP_METHOD = 'post'
        _no_auth(URL, HTTP_METHOD)
        _wrong_auth_type(URL, HTTP_METHOD)
        _bad_token(URL, HTTP_METHOD)

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
        self.logger.debug("test_create_new_channel url: %s", URL)
        result = _successful_call(URL, HTTP_METHOD, None,
            request_body, self._api_key)

        assert result.status_code == 200, result.reason

        response_body = result.json()
        # self.logger.debug(json.dumps(response_body, indent=4))

        single_channel_data = response_body
        CHANNEL_ID = single_channel_data['id']
        assert single_channel_data['href'] == \
            f"http://{TEST_EXTERNAL_HOST}:{TEST_EXTERNAL_PORT}/api/v1/channel/{CHANNEL_ID}"
        assert single_channel_data['public_read'] is True
        assert single_channel_data['public_write'] is True
        assert single_channel_data['sequenced'] is True
        assert single_channel_data['retention'] == {"min_age_days": 0, "max_age_days": 0, \
            "auto_prune": True}
        assert isinstance(single_channel_data['access_tokens'], list)
        assert single_channel_data['access_tokens'][0]['id'] == 1
        issued_token_bytes = \
            base64.urlsafe_b64decode(single_channel_data['access_tokens'][0]['token'])
        assert len(issued_token_bytes) == 64
        assert single_channel_data['access_tokens'][0]['description'] == "Owner"
        assert single_channel_data['access_tokens'][0]['can_read'] is True
        assert single_channel_data['access_tokens'][0]['can_write'] is True

    @pytest.mark.asyncio
    async def test_create_new_token_for_channel(self) -> None:
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()

        # handler: create_new_token_for_channel
        URL = "http://"+ TEST_EXTERNAL_HOST +":"+ str(TEST_EXTERNAL_PORT) + \
            "/api/v1/channel/manage/{channelid}/api-token"
        HTTP_METHOD = 'post'
        _no_auth(URL, HTTP_METHOD)
        _wrong_auth_type(URL, HTTP_METHOD)
        _bad_token(URL, HTTP_METHOD)

        request_body = {
          "description": "some description",
          "can_read": True,
          "can_write": False
        }
        url = URL.format(channelid=CHANNEL_ID)
        self.logger.debug("test_create_new_token_for_channel url: %s", url)
        result = _successful_call(url, HTTP_METHOD, None,
            request_body, self._api_key)

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
    def test_list_channels(self) -> None:
        # handler: list_channels
        URL = "http://"+ TEST_EXTERNAL_HOST +":"+ str(TEST_EXTERNAL_PORT) + \
            "/api/v1/channel/manage/list"
        HTTP_METHOD = 'get'
        _no_auth(URL, HTTP_METHOD)
        _wrong_auth_type(URL, HTTP_METHOD)
        _bad_token(URL, HTTP_METHOD)

        request_body = None
        self.logger.debug("test_list_channels url: %s", URL)
        result = _successful_call(URL, HTTP_METHOD, None,
            request_body, self._api_key)
        assert result.status_code == 200, result.reason

        response_body = result.json()
        # self.logger.debug(json.dumps(response_body, indent=4))

        assert isinstance(response_body, list)
        assert len(response_body) == 2
        for single_channel_data in response_body:
            # assert single_channel_data['href'] == \
            #   f"http://{TEST_HOST}:{TEST_PORT}/api/v1/channel/{CHANNEL_ID}"
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
    async def test_get_single_channel_details(self) -> None:
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()

        # handler: get_single_channel_details
        URL = "http://"+ TEST_EXTERNAL_HOST +":"+ str(TEST_EXTERNAL_PORT) + \
            "/api/v1/channel/manage/{channelid}"
        HTTP_METHOD = 'get'
        _no_auth(URL, HTTP_METHOD)
        _wrong_auth_type(URL, HTTP_METHOD)
        _bad_token(URL, HTTP_METHOD)

        request_body = None
        url = URL.format(channelid=CHANNEL_ID)
        self.logger.debug("test_get_single_channel_details url: %s", url)
        result = _successful_call(url, HTTP_METHOD, None,
            request_body, self._api_key)
        assert result.status_code == 200, result.reason

        response_body = result.json()
        # self.logger.debug(json.dumps(response_body, indent=4))

        single_channel_data = response_body
        assert single_channel_data['href'] == \
            f"http://{TEST_EXTERNAL_HOST}:{TEST_EXTERNAL_PORT}/api/v1/channel/{CHANNEL_ID}"
        assert single_channel_data['public_read'] is True
        assert single_channel_data['public_write'] is True
        assert single_channel_data['sequenced'] is True
        assert single_channel_data['retention'] == {"min_age_days": 0, "max_age_days": 0,
            "auto_prune": True}
        assert isinstance(single_channel_data['access_tokens'], list)
        assert isinstance(single_channel_data['access_tokens'][0]['id'], int)
        issued_token_bytes = \
            base64.urlsafe_b64decode(single_channel_data['access_tokens'][0]['token'])
        assert len(issued_token_bytes) == 64
        assert single_channel_data['access_tokens'][0]['description'] == "Owner"
        assert single_channel_data['access_tokens'][0]['can_read'] is True
        assert single_channel_data['access_tokens'][0]['can_write'] is True

    @pytest.mark.asyncio
    async def test_update_single_channel_properties(self) -> None:
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()

        # handler: update_single_channel_properties
        URL = "http://"+ TEST_EXTERNAL_HOST +":"+ str(TEST_EXTERNAL_PORT) + \
            "/api/v1/channel/manage/{channelid}"
        HTTP_METHOD = 'post'
        _no_auth(URL, HTTP_METHOD)
        _wrong_auth_type(URL, HTTP_METHOD)
        _bad_token(URL, HTTP_METHOD)

        request_body = {
            "public_read": True,
            "public_write": True,
            "locked": False
        }
        url = URL.format(channelid=CHANNEL_ID)
        self.logger.debug("test_update_single_channel_properties url: %s", url)
        result = _successful_call(url, HTTP_METHOD, None,
            request_body, self._api_key)
        assert result.status_code == 200, result.reason

        response_body = result.json()
        # self.logger.debug(json.dumps(response_body, indent=4))
        assert response_body == request_body

    @pytest.mark.asyncio
    async def test_get_token_details(self) -> None:
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
        # handler: get_token_details
        URL = 'http://{host}:{port}/api/v1/channel/manage/{channelid}/api-token/{tokenid}'\
            .format(host=TEST_EXTERNAL_HOST, port=TEST_EXTERNAL_PORT, channelid=CHANNEL_ID,
                tokenid=CHANNEL_READ_ONLY_TOKEN_ID)
        HTTP_METHOD = 'get'
        _no_auth(URL, HTTP_METHOD)
        _wrong_auth_type(URL, HTTP_METHOD)
        _bad_token(URL, HTTP_METHOD)

        request_body = None
        self.logger.debug("test_get_token_details url: %s", URL)
        result = _successful_call(URL, HTTP_METHOD, None,
            request_body, self._api_key)

        assert result.status_code == 200, result.reason

        response_body = result.json()
        self.logger.debug(json.dumps(response_body, indent=4))
        assert response_body == expected_response_body

    @pytest.mark.asyncio
    async def test_get_list_of_tokens(self) -> None:
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

        # handler: get_list_of_tokens
        URL = 'http://{host}:{port}/api/v1/channel/manage/{channelid}/api-token'\
            .format(host=TEST_EXTERNAL_HOST, port=TEST_EXTERNAL_PORT, channelid=CHANNEL_ID)
        HTTP_METHOD = 'get'
        _no_auth(URL, HTTP_METHOD)
        _wrong_auth_type(URL, HTTP_METHOD)
        _bad_token(URL, HTTP_METHOD)

        request_body = None
        self.logger.debug("test_get_list_of_tokens url: %s", URL)
        result = _successful_call(URL, HTTP_METHOD, None,
            request_body, self._api_key)

        assert result.status_code == 200, result.reason

        response_body = result.json()
        self.logger.debug(json.dumps(response_body, indent=4))
        assert response_body == expected_response_body

    # MESSAGE MANAGEMENT APIS - USE CHANNEL-SPECIFIC BEARER TOKEN NOW

    @pytest.mark.asyncio
    async def test_write_message_no_content_type_should_raise_400(self) -> None:
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()

        # handler: write_message
        URL = 'http://{host}:{port}/api/v1/channel/{channelid}'.format(host=TEST_EXTERNAL_HOST,
            port=TEST_EXTERNAL_PORT, channelid=CHANNEL_ID)
        HTTP_METHOD = 'post'
        _no_auth(URL, HTTP_METHOD)
        _wrong_auth_type(URL, HTTP_METHOD)
        _bad_token(URL, HTTP_METHOD, headers={'Content-Type': 'application/json'})

        request_body = {"key": "value"}
        self.logger.debug("test_write_message_no_content_type_should_raise_400 url: %s", URL)
        headers = {
            "Content-Type": "",
        }
        result = _successful_call(URL, HTTP_METHOD, headers, request_body, CHANNEL_BEARER_TOKEN)
        assert result.status_code == HTTPStatus.BAD_REQUEST, result.reason
        assert result.reason is not None

    @pytest.mark.asyncio
    async def test_write_message_read_only_token_should_fail(self) -> None:
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()
        CHANNEL_READ_ONLY_TOKEN_ID, CHANNEL_READ_ONLY_TOKEN = \
            await self._create_read_only_token(CHANNEL_ID)

        headers = {}
        headers["Content-Type"] = "application/json"
        request_body = {
            "key": "value"
        }

        # handler: write_message
        URL = f"http://{TEST_EXTERNAL_HOST}:{TEST_EXTERNAL_PORT}/api/v1/channel/{CHANNEL_ID}"
        HTTP_METHOD = 'post'
        _no_auth(URL, HTTP_METHOD)
        _wrong_auth_type(URL, HTTP_METHOD)
        _bad_token(URL, HTTP_METHOD, headers={'Content-Type': 'application/json'})

        self.logger.debug("test_write_message_read_only_token_should_fail url: %s", URL)
        result = _successful_call(URL, HTTP_METHOD, headers,
            request_body, CHANNEL_READ_ONLY_TOKEN)

        assert result.status_code == 401, result.reason

    def _write_message(self, CHANNEL_ID: str, CHANNEL_BEARER_TOKEN: str) -> requests.Response:
        headers = {}
        headers["Content-Type"] = "application/json"
        request_body = {
            "key": "value"
        }
        # handler: write_message
        URL = f"http://{TEST_EXTERNAL_HOST}:{TEST_EXTERNAL_PORT}/api/v1/channel/{CHANNEL_ID}"
        HTTP_METHOD = 'post'
        _no_auth(URL, HTTP_METHOD)
        _wrong_auth_type(URL, HTTP_METHOD)
        _bad_token(URL, HTTP_METHOD, headers={'Content-Type': 'application/json'})

        self.logger.debug("test_write_message url: %s", URL)
        result = _successful_call(URL, HTTP_METHOD, headers,
            request_body, CHANNEL_BEARER_TOKEN)
        assert result.status_code == 200, result.reason
        return result

    @pytest.mark.asyncio
    async def test_write_message(self) -> None:
        """Uses CHANNEL_BEARER_TOKEN to write messages for the CHANNEL_READ_ONLY_TOKEN to read."""
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()

        headers = {}
        headers["Content-Type"] = "application/json"
        request_body = {
            "key": "value"
        }
        expected_response_body = base64.b64encode(json.dumps(request_body).encode('utf-8')).decode()

        # handler: write_message
        URL = f"http://{TEST_EXTERNAL_HOST}:{TEST_EXTERNAL_PORT}/api/v1/channel/{CHANNEL_ID}"
        HTTP_METHOD = 'post'
        _no_auth(URL, HTTP_METHOD)
        _wrong_auth_type(URL, HTTP_METHOD)
        _bad_token(URL, HTTP_METHOD, headers={'Content-Type': 'application/json'})

        self.logger.debug("test_write_message url: %s", URL)
        result = _successful_call(URL, HTTP_METHOD, headers,
            request_body, CHANNEL_BEARER_TOKEN)

        assert result.status_code == 200, result.reason

        response_body = result.json()
        assert isinstance(response_body['sequence'], int)
        assert isinstance(from_isoformat(response_body['received']), datetime)
        assert response_body['content_type'] == 'application/json'
        assert response_body['payload'] == expected_response_body

    @pytest.mark.asyncio
    async def test_get_messages_head(self) -> None:
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()
        CHANNEL_READ_ONLY_TOKEN_ID, CHANNEL_READ_ONLY_TOKEN = \
            await self._create_read_only_token(CHANNEL_ID)
        self._write_message(CHANNEL_ID, CHANNEL_BEARER_TOKEN)

        # handler: get_messages
        URL = f"http://{TEST_EXTERNAL_HOST}:{TEST_EXTERNAL_PORT}/api/v1/channel/{CHANNEL_ID}"
        HTTP_METHOD = 'head'
        _no_auth(URL, HTTP_METHOD)
        _wrong_auth_type(URL, HTTP_METHOD)
        _bad_token(URL, HTTP_METHOD)

        self.logger.debug("test_get_messages_head url: %s", URL)
        result = _successful_call(URL, HTTP_METHOD, None, None,
            CHANNEL_READ_ONLY_TOKEN)
        assert result.headers['ETag'] == "1"
        assert result.content == b''

    @pytest.mark.asyncio
    async def test_get_messages_unread_should_get_one(self) -> None:
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()
        CHANNEL_READ_ONLY_TOKEN_ID, CHANNEL_READ_ONLY_TOKEN = \
            await self._create_read_only_token(CHANNEL_ID)
        _response = self._write_message(CHANNEL_ID, CHANNEL_BEARER_TOKEN)

        # handler: get_messages
        query_params = "?unread=true"
        URL = f"http://{TEST_EXTERNAL_HOST}:{TEST_EXTERNAL_PORT}/api/v1/channel/{CHANNEL_ID}" + \
            query_params
        HTTP_METHOD = 'get'
        _no_auth(URL, HTTP_METHOD)
        _wrong_auth_type(URL, HTTP_METHOD)
        _bad_token(URL, HTTP_METHOD)

        expected_response_body = base64.b64encode(
            json.dumps({"key": "value"}).encode('utf-8')).decode()

        self.logger.debug("test_get_messages_head url: %s", URL)
        result = _successful_call(URL, HTTP_METHOD, None, None,
            CHANNEL_READ_ONLY_TOKEN)
        assert result.headers['ETag'] == "1"
        response_body = result.json()
        assert isinstance(response_body, list)
        assert response_body[0]['sequence'] == 1
        assert isinstance(from_isoformat(response_body[0]['received']), datetime)
        assert response_body[0]['content_type'] == 'application/json'
        assert response_body[0]['payload'] == expected_response_body

    @pytest.mark.asyncio
    async def test_mark_message_read_or_unread(self) -> None:
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()
        CHANNEL_READ_ONLY_TOKEN_ID, CHANNEL_READ_ONLY_TOKEN = \
            await self._create_read_only_token(CHANNEL_ID)
        _response = self._write_message(CHANNEL_ID, CHANNEL_BEARER_TOKEN)

        # handler: mark_message_read_or_unread
        sequence = 1
        query_params = "?older=true"
        URL = f"http://{TEST_EXTERNAL_HOST}:{TEST_EXTERNAL_PORT}"+ \
            f"/api/v1/channel/{CHANNEL_ID}/{sequence}" + query_params
        HTTP_METHOD = 'post'
        _no_auth(URL, HTTP_METHOD)
        _wrong_auth_type(URL, HTTP_METHOD)
        _bad_token(URL, HTTP_METHOD)

        body = {"read": True}
        result = _successful_call(URL, HTTP_METHOD, None, body,
            CHANNEL_READ_ONLY_TOKEN)
        assert result.status_code == 200, result.reason

        sequence = 2
        query_params = "?older=true"
        URL = f"http://{TEST_EXTERNAL_HOST}:{TEST_EXTERNAL_PORT}"+ \
            f"/api/v1/channel/{CHANNEL_ID}/{sequence}" + query_params
        result = _successful_call(URL, HTTP_METHOD, None, body,
            CHANNEL_READ_ONLY_TOKEN)
        assert result.status_code == 404, result.reason
        assert result.reason is not None

    @pytest.mark.asyncio
    async def test_delete_message_read_only_token_should_fail(self) -> None:
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()
        CHANNEL_READ_ONLY_TOKEN_ID, CHANNEL_READ_ONLY_TOKEN = \
            await self._create_read_only_token(CHANNEL_ID)
        _response = self._write_message(CHANNEL_ID, CHANNEL_BEARER_TOKEN)

        # handler: delete_message
        sequence = 1
        URL = f"http://{TEST_EXTERNAL_HOST}:{TEST_EXTERNAL_PORT}"+ \
            f"/api/v1/channel/{CHANNEL_ID}/{sequence}"
        HTTP_METHOD = 'delete'
        _no_auth(URL, HTTP_METHOD)
        _wrong_auth_type(URL, HTTP_METHOD)
        _bad_token(URL, HTTP_METHOD)

        sequence = 1
        url = URL.format(channelid=CHANNEL_ID, sequence=sequence)
        result = _successful_call(url, HTTP_METHOD, None, None,
            CHANNEL_READ_ONLY_TOKEN)
        assert result.status_code == 401, result.reason

        sequence = 2
        url = URL.format(channelid=CHANNEL_ID, sequence=sequence)
        result = _successful_call(url, HTTP_METHOD, None, None,
            CHANNEL_READ_ONLY_TOKEN)
        assert result.status_code == 401, result.reason
        assert result.reason is not None

    @pytest.mark.asyncio
    async def test_delete_message_should_succeed(self) -> None:
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()
        _response = self._write_message(CHANNEL_ID, CHANNEL_BEARER_TOKEN)

        sequence = 1
        URL = f"http://{TEST_EXTERNAL_HOST}:{TEST_EXTERNAL_PORT}"+ \
            f"/api/v1/channel/{CHANNEL_ID}/{sequence}"
        HTTP_METHOD = 'delete'
        _no_auth(URL, HTTP_METHOD)
        _wrong_auth_type(URL, HTTP_METHOD)
        _bad_token(URL, HTTP_METHOD)

        result = _successful_call(URL, HTTP_METHOD, None, None,
            CHANNEL_BEARER_TOKEN)
        assert result.status_code == 200, result.reason

        sequence = 2
        url = URL.format(channelid=CHANNEL_ID, sequence=sequence)
        result = _successful_call(url, HTTP_METHOD, None, None,
            CHANNEL_BEARER_TOKEN)
        assert result.status_code == 404, result.reason
        assert result.reason is not None

    async def _subscribe_to_msg_box_notifications(self, url: str, msg_box_api_token: str,
            expected_count: int, completion_event: asyncio.Event) -> None:

        count = 0
        async with aiohttp.ClientSession() as session:
            try:
                async with session.ws_connect(url + f"?token={msg_box_api_token}", timeout=5.0) \
                        as ws:
                    self.logger.info('Connected to %s', url)
                    async for msg in ws:
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            content = json.loads(msg.data)
                            self.logger.info('New message from msg box: %s', content)

                            count += 1
                            if expected_count == count:
                                self.logger.debug("Received all %s messages", expected_count)
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
    def test_channels_websocket_bad_auth_should_fail(self) -> None:
        async def wait_on_sub(url: str, msg_box_api_token: str, expected_count: int,
                completion_event: asyncio.Event) -> None:
            try:
                await self._subscribe_to_msg_box_notifications(url, msg_box_api_token,
                    expected_count, completion_event)
            except WebsocketUnauthorizedException:
                self.logger.debug("Websocket unauthorized - bad token")
                assert True  # Auth should failed

        completion_event = asyncio.Event()
        url = WS_URL_TEMPLATE_MSG_BOX.format(channelid=CHANNEL_ID)
        asyncio.run(wait_on_sub(url, "BAD_BEARER_TOKEN", 0, completion_event))

    @pytest.mark.asyncio
    def test_channels_websocket(self) -> None:
        logger = logging.getLogger("websocket-test")
        async def wait_on_sub(url: str, msg_box_api_token: str, expected_count: int,
                completion_event: asyncio.Event) -> None:
            try:
                await self._subscribe_to_msg_box_notifications(url, msg_box_api_token,
                    expected_count, completion_event)
            except WebsocketUnauthorizedException:
                self.logger.debug("Auth failed")
                assert False  # Auth should have passed

        async def push_messages(CHANNEL_ID: str, CHANNEL_BEARER_TOKEN: str,
                expected_msg_count: int) -> None:
            for i in range(expected_msg_count):
                headers = {}
                headers["Content-Type"] = "application/json"
                headers["Authorization"] = f"Bearer {CHANNEL_BEARER_TOKEN}"
                request_body = {"key": "value"}

                url = f"http://{TEST_EXTERNAL_HOST}:{TEST_EXTERNAL_PORT}" + \
                    f"/api/v1/channel/{CHANNEL_ID}"

                async with aiohttp.ClientSession() as session:
                    headers = {"Authorization": f"Bearer {CHANNEL_BEARER_TOKEN}"}
                    async with session.post(url, headers=headers, json=request_body) as resp:
                        self.logger.debug("push_messages = %s", await resp.json())
                        assert resp.status == 200, resp.reason

        async def main() -> None:
            CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = \
                await self._create_new_channel()
            CHANNEL_READ_ONLY_TOKEN_ID, CHANNEL_READ_ONLY_TOKEN = \
                await self._create_read_only_token(CHANNEL_ID)

            EXPECTED_MSG_COUNT = 10
            logger.debug("CHANNEL_ID: %s", CHANNEL_ID)
            logger.debug("CHANNEL_BEARER_TOKEN: %s", CHANNEL_BEARER_TOKEN)
            logger.debug("CHANNEL_READ_ONLY_TOKEN: %s", CHANNEL_READ_ONLY_TOKEN)

            completion_event = asyncio.Event()
            url = WS_URL_TEMPLATE_MSG_BOX.format(channelid=CHANNEL_ID)
            task1 = asyncio.create_task(wait_on_sub(url, CHANNEL_BEARER_TOKEN, EXPECTED_MSG_COUNT,
                completion_event))
            await asyncio.sleep(3)
            task2 = asyncio.create_task(push_messages(CHANNEL_ID, CHANNEL_BEARER_TOKEN,
                EXPECTED_MSG_COUNT))
            await asyncio.gather(task1, task2)
            await completion_event.wait()

        asyncio.run(main())

    @pytest.mark.asyncio
    def test_general_purpose_websocket_bad_auth_should_fail(self) -> None:
        async def wait_on_sub(url: str, api_token: str,
                              expected_count: int, completion_event: asyncio.Event) -> None:
            try:
                await _subscribe_to_general_notifications_peer_channels(url,
                    api_token, expected_count, completion_event)
            except WebsocketUnauthorizedException:
                self.logger.debug("Websocket unauthorized - bad token")
                assert True  # Auth should failed

        completion_event = asyncio.Event()
        url = WS_URL_GENERAL
        asyncio.run(wait_on_sub(url, "BAD_BEARER_TOKEN", 0, completion_event))

    @pytest.mark.asyncio
    def test_general_purpose_websocket_peer_channel_notifications(self) -> None:
        logger = logging.getLogger("websocket-test")
        async def manage_general_websocket_connection(url: str, api_token: str, expected_count: int,
                completion_event: asyncio.Event) -> None:
            try:
                await _subscribe_to_general_notifications_peer_channels(
                    url, api_token, expected_count, completion_event)
            except WebsocketUnauthorizedException:
                self.logger.debug("Auth failed")
                assert False  # Auth should have passed

        async def push_messages(CHANNEL_ID: str, CHANNEL_BEARER_TOKEN: str,
                expected_msg_count: int) -> None:
            for i in range(expected_msg_count):
                headers = {}
                headers["Content-Type"] = "application/json"
                headers["Authorization"] = f"Bearer {CHANNEL_BEARER_TOKEN}"
                request_body = {"key": "value"}

                url = f"http://{TEST_EXTERNAL_HOST}:{TEST_EXTERNAL_PORT}"+ \
                    f"/api/v1/channel/{CHANNEL_ID}"

                async with aiohttp.ClientSession() as session:
                    headers = {"Authorization": f"Bearer {CHANNEL_BEARER_TOKEN}"}

                    async with session.post(url, headers=headers, json=request_body) as resp:
                        self.logger.debug("push_messages = %s", await resp.json())
                        assert resp.status == 200, resp.reason

        async def main() -> None:
            CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = \
                await self._create_new_channel()
            CHANNEL_READ_ONLY_TOKEN_ID, CHANNEL_READ_ONLY_TOKEN = \
                await self._create_read_only_token(CHANNEL_ID)

            EXPECTED_MSG_COUNT = 10
            logger.debug("CHANNEL_ID: %s", CHANNEL_ID)
            logger.debug("CHANNEL_BEARER_TOKEN: %s", CHANNEL_BEARER_TOKEN)
            logger.debug("CHANNEL_READ_ONLY_TOKEN: %s", CHANNEL_READ_ONLY_TOKEN)

            completion_event = asyncio.Event()
            url = WS_URL_GENERAL
            task1 = asyncio.create_task(
                manage_general_websocket_connection(url, self._api_key, EXPECTED_MSG_COUNT,
                    completion_event))
            await asyncio.sleep(3)
            task2 = asyncio.create_task(push_messages(CHANNEL_ID, CHANNEL_BEARER_TOKEN,
                EXPECTED_MSG_COUNT))
            await asyncio.gather(task1, task2)
            await completion_event.wait()

        asyncio.run(main())

    @pytest.mark.asyncio
    async def test_revoke_selected_token(self) -> None:
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()
        CHANNEL_READ_ONLY_TOKEN_ID, CHANNEL_READ_ONLY_TOKEN = \
            await self._create_read_only_token(CHANNEL_ID)

        # handler: revoke_selected_token
        URL = 'http://{host}:{port}/api/v1/channel/manage/{channelid}/api-token/{tokenid}'\
            .format(host=TEST_EXTERNAL_HOST, port=TEST_EXTERNAL_PORT, channelid=CHANNEL_ID,
                tokenid=CHANNEL_READ_ONLY_TOKEN_ID)
        HTTP_METHOD = 'delete'
        _no_auth(URL, HTTP_METHOD)
        _wrong_auth_type(URL, HTTP_METHOD)
        _bad_token(URL, HTTP_METHOD)

        good_bearer_token = self._api_key
        request_body = None
        self.logger.debug("test_revoke_selected_token url: %s", URL)
        result = _successful_call(URL, HTTP_METHOD, None,
            request_body, good_bearer_token)

        assert result.status_code == web.HTTPNoContent.status_code

    def _revoke_token(self, CHANNEL_ID: str, CHANNEL_READ_ONLY_TOKEN_ID: str) -> requests.Response:
        # handler: revoke_selected_token
        URL = 'http://{host}:{port}/api/v1/channel/manage/{channelid}/api-token/{tokenid}'\
            .format(host=TEST_EXTERNAL_HOST, port=TEST_EXTERNAL_PORT, channelid=CHANNEL_ID,
                tokenid=CHANNEL_READ_ONLY_TOKEN_ID)
        HTTP_METHOD = 'delete'

        good_bearer_token = self._api_key
        request_body = None
        self.logger.debug("test_revoke_selected_token url: %s", URL)
        result = _successful_call(URL, HTTP_METHOD, None,
            request_body, good_bearer_token)
        return result

    @pytest.mark.asyncio
    async def test_expired_token_should_fail(self) -> None:
        CHANNEL_ID, CHANNEL_BEARER_TOKEN, CHANNEL_BEARER_TOKEN_ID = await self._create_new_channel()
        CHANNEL_READ_ONLY_TOKEN_ID, CHANNEL_READ_ONLY_TOKEN = \
            await self._create_read_only_token(CHANNEL_ID)
        self._revoke_token(CHANNEL_ID, CHANNEL_READ_ONLY_TOKEN_ID)

        # handler: get_token_details
        URL = 'http://{host}:{port}/api/v1/channel/manage/{channelid}/api-token/{tokenid}'\
            .format(host=TEST_EXTERNAL_HOST, port=TEST_EXTERNAL_PORT, channelid=CHANNEL_ID,
                tokenid=CHANNEL_READ_ONLY_TOKEN_ID)
        HTTP_METHOD = 'get'
        _no_auth(URL, HTTP_METHOD)
        _wrong_auth_type(URL, HTTP_METHOD)
        _bad_token(URL, HTTP_METHOD)

        expired_bearer_token = CHANNEL_READ_ONLY_TOKEN
        request_body = None
        self.logger.debug("test_revoke_selected_token url: %s", URL)
        result = _successful_call(URL, HTTP_METHOD, None,
            request_body, expired_bearer_token)

        assert result.status_code == 401

    @pytest.mark.asyncio
    async def test_delete_channel(self) -> None:
        assert ApplicationState.singleton_reference is not None
        application_state = ApplicationState.singleton_reference()
        assert application_state is not None

        await self._create_new_channel()

        @replace_db_context_with_connection
        def read(db: sqlite3.Connection) -> list[str]:
            rows = db.execute("SELECT externalid FROM msg_box").fetchall()
            assert len(rows) > 0
            return [ row[0] for row in rows ]

        channel_ids_for_deletion = read(application_state.database_context)

        URL_TEMPLATE = "http://"+ TEST_EXTERNAL_HOST +":"+ str(TEST_EXTERNAL_PORT) + \
            "/api/v1/channel/manage/{channelid}"
        HTTP_METHOD = 'delete'
        _no_auth(URL_TEMPLATE, HTTP_METHOD)
        _wrong_auth_type(URL_TEMPLATE, HTTP_METHOD)
        _bad_token(URL_TEMPLATE, HTTP_METHOD)

        good_bearer_token = self._api_key
        for channel_id in channel_ids_for_deletion:
            url = URL_TEMPLATE.format(channelid=channel_id)
            self.logger.debug("test_delete_channel url: %s", url)
            result = _successful_call(url, HTTP_METHOD, None,
                None, good_bearer_token)
            assert result.status_code == web.HTTPNoContent.status_code

        @replace_db_context_with_connection
        def read2(db: sqlite3.Connection) -> None:
            rows = db.execute("SELECT * FROM msg_box").fetchall()
            assert len(rows) == 0
        read2(application_state.database_context)

        @replace_db_context_with_connection
        def read3(db: sqlite3.Connection) -> None:
            rows = db.execute("SELECT * FROM msg_box_api_token").fetchall()
            assert len(rows) == 0
        read3(application_state.database_context)

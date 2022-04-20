import asyncio
import logging
from typing import Optional

import aiohttp
from aiohttp import WSServerHandshakeError
import pytest
import requests
from _pytest.outcomes import Skipped

from unittests.conftest import _assert_binary_tip_structure_correct, \
    _assert_tip_notification_structure, _assert_tip_structure_correct, REGTEST_GENESIS_BLOCK_HASH, \
    _successful_call, TEST_EXTERNAL_HOST, TEST_EXTERNAL_PORT, WS_URL_HEADERS


class TestAiohttpRESTAPI:
    logger = logging.getLogger("TestAiohttpRESTAPI")

    @classmethod
    def setup_class(cls) -> None:
        pass

    def setup_method(self) -> None:
        pass

    def teardown_method(self) -> None:
        pass

    @classmethod
    def teardown_class(cls) -> None:
        pass

    def test_get_headers_by_height(self) -> None:
        expected = [
            {'hash': '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206',
             'version': 1,
             'prevBlockHash': '0000000000000000000000000000000000000000000000000000000000000000',
             'merkleRoot': '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b',
             'creationTimestamp': 1296688602,
             'difficultyTarget': 545259519,
             'nonce': 2,
             'transactionCount': 0,
             'work': 2}
        ]
        query_params = '?height=0'
        URL = "http://"+ TEST_EXTERNAL_HOST +":"+ str(TEST_EXTERNAL_PORT) + \
            "/api/v1/headers/by-height" + query_params
        HTTP_METHOD = 'get'
        self.logger.debug("test_get_headers_by_height url: %s", URL)
        result: requests.Response = _successful_call(URL, HTTP_METHOD, None)
        if result.status_code == 503:
            pytest.skip(result.reason)

        assert expected == result.json()

    def test_get_header(self) -> None:
        expected = {
            'hash': '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206',
            'version': 1,
            'prevBlockHash': '0000000000000000000000000000000000000000000000000000000000000000',
            'merkleRoot': '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b',
            'creationTimestamp': 1296688602,
            'difficultyTarget': 545259519,
            'nonce': 2,
            'transactionCount': 0,
            'work': 2
        }
        URL = "http://{host}:{port}/api/v1/headers/{hash}".format(host=TEST_EXTERNAL_HOST,
            port=TEST_EXTERNAL_PORT, hash=REGTEST_GENESIS_BLOCK_HASH)
        HTTP_METHOD = 'get'
        self.logger.debug("test_get_header url: %s", URL)
        result: requests.Response = _successful_call(URL, HTTP_METHOD, None)
        if result.status_code == 503:
            pytest.skip(result.reason)

        assert expected == result.json()

    def test_get_header_binary(self) -> None:
        expected = \
            b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
            b';\xa3\xed\xfdz{\x12\xb2z\xc7,>gv\x8fa\x7f\xc8\x1b\xc3\x88\x8aQ2:\x9f\xb8' \
            b'\xaaK\x1e^J\xda\xe5IM\xff\xff\x7f \x02\x00\x00\x00'

        URL = "http://{host}:{port}/api/v1/headers/{hash}".format(host=TEST_EXTERNAL_HOST,
            port=TEST_EXTERNAL_PORT, hash=REGTEST_GENESIS_BLOCK_HASH)
        HTTP_METHOD = 'get'
        self.logger.debug("test_get_header url: %s", URL)
        request_headers = {'Accept': 'application/octet-stream'}
        result: requests.Response = _successful_call(URL, HTTP_METHOD, request_headers)
        if result.status_code == 503:
            pytest.skip(result.reason)
        assert expected == result.content

    def test_get_chain_tips_json(self) -> None:
        query_params = '?longest_chain=1'
        URL = "http://"+ TEST_EXTERNAL_HOST +":"+ str(TEST_EXTERNAL_PORT) + \
            "/api/v1/headers/tips" + query_params
        HTTP_METHOD = 'get'
        self.logger.debug("test_get_chain_tips url: %s", URL)
        result: requests.Response = _successful_call(URL,
            HTTP_METHOD, None)
        if result.status_code == 503:
            pytest.skip(result.reason)

        response_json = result.json()
        assert isinstance(response_json, list)
        _assert_tip_structure_correct(response_json[0])

    def test_get_chain_tips_binary(self) -> None:
        query_params = '?longest_chain=1'
        URL = "http://"+ TEST_EXTERNAL_HOST +":"+ str(TEST_EXTERNAL_PORT) + \
            "/api/v1/headers/tips" + query_params
        HTTP_METHOD = 'get'
        self.logger.debug("test_get_chain_tips url: %s", URL)
        request_headers = {'Accept': 'application/octet-stream'}
        result: requests.Response = _successful_call(URL,
            HTTP_METHOD, request_headers)
        if result.status_code == 503:
            pytest.skip(result.reason)

        response = result.content
        assert isinstance(response, bytes)
        _assert_binary_tip_structure_correct(response)

    async def _subscribe_to_headers_notifications(self, expected_count: int,
            completion_event: asyncio.Event) -> bool:
        count = 0
        try:
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(WS_URL_HEADERS, timeout=5.0) as ws:
                    self.logger.info('Connected to %s', WS_URL_HEADERS)

                    async for msg in ws:
                        content = msg.data
                        self.logger.info('New header notification: %s', content)

                        result = _assert_tip_notification_structure(content)
                        if not result:
                            return False

                        count += 1
                        if count == expected_count:
                            self.logger.info("Received %d headers successfully", expected_count)
                            completion_event.set()
                            return result
                        if msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                            return False
            return False
        except WSServerHandshakeError as e:
            raise e
        except Exception:
            self.logger.exception("Unexpected exception in _subscribe_to_headers_notifications")
            return False

    def test_headers_websocket(self) -> Optional[Skipped]:
        # Skip if HeaderSV APIs unavailable
        query_params = '?longest_chain=1'
        URL = "http://"+ TEST_EXTERNAL_HOST +":"+ str(TEST_EXTERNAL_PORT) + \
            "/api/v1/headers/tips" + query_params
        HTTP_METHOD = 'get'
        self.logger.debug("test_get_chain_tips url: %s", URL)
        result: requests.Response = _successful_call(URL,
            HTTP_METHOD, None)
        if result.status_code == 503:
            pytest.skip(result.reason)

        async def wait_on_sub(expected_count: int, completion_event: asyncio.Event) -> None:
            try:
                await self._subscribe_to_headers_notifications(expected_count, completion_event)
            except WSServerHandshakeError as e:
                if e.status == 401:
                    self.logger.debug("Unauthorized - Bad Bearer Token")
                    assert False  # i.e. auth should have passed

        async def mine_blocks(expected_msg_count: int) -> Optional[str]:
            for i in range(expected_msg_count):
                url = "http://rpcuser:rpcpassword@127.0.0.1:18332"
                try:
                    async with aiohttp.ClientSession() as session:
                        request_body = {"jsonrpc": "2.0", "method": "generate", "params": [1],
                                        "id": 1}
                        async with session.post(url, json=request_body) as resp:
                            self.logger.debug("mine_blocks = %s", await resp.json())
                            assert resp.status == 200, resp.reason
                    await asyncio.sleep(2)
                except aiohttp.ClientConnectorError:
                    return "SKIP"
            return None

        async def main() -> Optional[Skipped]:
            EXPECTED_MSG_COUNT = 2

            completion_event = asyncio.Event()
            fut1 = asyncio.create_task(wait_on_sub(EXPECTED_MSG_COUNT, completion_event))
            await asyncio.sleep(3)
            result = await mine_blocks(EXPECTED_MSG_COUNT)
            if result == "SKIP":
                fut1.cancel()
                return pytest.skip("Bitcoin Regtest node unavailable")
            await completion_event.wait()
            fut1.result()  # skip or pass
            return None

        return asyncio.run(main())

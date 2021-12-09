import asyncio
import json
import logging
import os

import aiohttp
import bitcoinx
import pytest
import requests
from aiohttp import web
from electrumsv_node import electrumsv_node

from esv_reference_server.errors import Error
from unittests.conftest import API_ROUTE_DEFS, _successful_call, TEST_MASTER_BEARER_TOKEN, TEST_PORT

REGTEST_GENESIS_BLOCK_HASH = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
WS_URL_HEADERS = f"http://localhost:{TEST_PORT}/api/v1/chain/tips/websocket"


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

    pytest.mark.skipif(os.environ['EXPOSE_HEADER_SV_APIS'] == '0')
    def test_get_headers_by_height(self):
        route = API_ROUTE_DEFS['get_headers_by_height']
        self.logger.debug(f"test_get_headers_by_height url: {route.url}")
        result: requests.Response = _successful_call(route.url + "?height=0", route.http_method, None,
            good_bearer_token=TEST_MASTER_BEARER_TOKEN)
        if result.status_code == 503:
            pytest.skip(result.reason)

    def test_get_header(self):
        route = API_ROUTE_DEFS['get_header']
        self.logger.debug(f"test_get_header url: {route.url}")
        result: requests.Response = _successful_call(route.url.format(hash=REGTEST_GENESIS_BLOCK_HASH),
            route.http_method, None, good_bearer_token=TEST_MASTER_BEARER_TOKEN)
        if result.status_code == 503:
            pytest.skip(result.reason)

    def test_get_chain_tips(self):
        route = API_ROUTE_DEFS['get_chain_tips']
        self.logger.debug(f"test_get_chain_tips url: {route.url}")
        result: requests.Response = _successful_call(route.url,
            route.http_method, None, good_bearer_token=TEST_MASTER_BEARER_TOKEN)
        if result.status_code == 503:
            pytest.skip(result.reason)


    def test_get_peers(self):
        route = API_ROUTE_DEFS['get_peers']
        self.logger.debug(f"test_get_peers url: {route.url}")
        result: requests.Response = _successful_call(route.url,
            route.http_method, None, good_bearer_token=TEST_MASTER_BEARER_TOKEN)
        if result.status_code == 503:
            pytest.skip(result.reason)

    def test_channels_websocket(self):
        logger = logging.getLogger("websocket--headers-test")
        async def wait_on_sub(api_token: str, expected_count: int, completion_event: asyncio.Event):
            await subscribe_to_headers_notifications(api_token, expected_count, completion_event)

        async def subscribe_to_headers_notifications(api_token: str, expected_count: int,
                completion_event: asyncio.Event) -> None:
            count = 0
            async with aiohttp.ClientSession() as session:
                headers = {"Authorization": f"Bearer {api_token}"}
                async with session.ws_connect(WS_URL_HEADERS, headers=headers, timeout=5.0) as ws:
                    logger.info(f'Connected to {WS_URL_HEADERS}')

                    async for msg in ws:
                        content = json.loads(msg.data)
                        self.logger.info(f'New message from msg box: {content}')

                        if isinstance(content, dict) and content.get('error'):
                            error: Error = Error.from_websocket_dict(content)
                            self.logger.info(f"Websocket error: {error}")
                            if error.status == web.HTTPUnauthorized.status_code:
                                raise web.HTTPUnauthorized()

                        count += 1
                        if count == expected_count:
                            logger.info(f"Received {expected_count} headers successfully")
                            completion_event.set()
                            return
                        if msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                            break

        async def mine_blocks(expected_msg_count: int):
            for i in range(expected_msg_count):
                url = "http://rpcuser:rpcpassword@127.0.0.1:18332"
                try:
                    async with aiohttp.ClientSession() as session:
                        request_body = {"jsonrpc": "2.0", "method": "generate", "params": [1], "id": 1}
                        async with session.post(url, json=request_body) as resp:
                            self.logger.debug(f"mine_blocks = {await resp.json()}")
                            assert resp.status == 200, resp.reason
                    await asyncio.sleep(2)
                except aiohttp.ClientConnectorError:
                    pytest.skip("Bitcoin Regtest node unavailable")

        async def main():
            EXPECTED_MSG_COUNT = 3

            completion_event = asyncio.Event()
            asyncio.create_task(wait_on_sub(TEST_MASTER_BEARER_TOKEN, EXPECTED_MSG_COUNT,
                completion_event))
            await asyncio.sleep(3)
            await mine_blocks(EXPECTED_MSG_COUNT)
            await completion_event.wait()

        asyncio.run(main())

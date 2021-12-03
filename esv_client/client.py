"""
Copyright(c) 2021 Bitcoin Association.
Distributed under the Open BSV software license, see the accompanying file LICENSE
"""

import asyncio
import json
import logging
import sys

import traceback
import aiohttp
import bitcoinx
from aiohttp import ClientConnectorError, web
from aiohttp.web_exceptions import HTTPClientError

from esv_reference_server.errors import Error

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 47124
WS_URL_HEADERS = "http://localhost:47124/api/v1/chain/tips/websocket"
WS_URL_TEMPLATE_MSG_BOX = "http://localhost:47124/api/v1/channel/{channelid}/notify"


class MockApplicationState:

    def __init__(self) -> None:
        # some state
        pass


class ElectrumSVClient:
    def __init__(self, app_state: MockApplicationState) -> None:
        self.app_state = app_state
        self.logger = logging.getLogger("electrumsv-client")

    async def subscribe_to_headers_notifications(self, api_token: str) -> None:
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {api_token}"}
            async with session.ws_connect(WS_URL_HEADERS, headers=headers, timeout=5.0) as ws:
                print(f'Connected to {WS_URL_HEADERS}')

                async for msg in ws:
                    new_tip_hash = bitcoinx.hash_to_hex_str(bitcoinx.double_sha256(msg.data[0:80]))
                    new_tip_height = bitcoinx.unpack_be_uint32(msg.data[80:84])[0]
                    print('Message new chain tip hash: ', new_tip_hash, 'height: ', new_tip_height)
                    if msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                        break

    async def subscribe_to_msg_box_notifications(self, url: str, msg_box_api_token: str) -> None:
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {msg_box_api_token}"}
            async with session.ws_connect(url, headers=headers, timeout=5.0) as ws:
                print(f'Connected to {url}')

                async for msg in ws:
                    print('New message from msg box: ', msg.data)
                    msg: aiohttp.WSMessage
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        content = json.loads(msg.data)
                        if content.get('error'):
                            error: Error = Error.from_websocket_dict(content)
                            print(f"Websocket error: {error}")
                            if error.status == web.HTTPUnauthorized.status_code:
                                raise web.HTTPUnauthorized()

                    if msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.ERROR,
                            aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSING):
                        print("CLOSED")
                        break


# entrypoint to main event loop
async def main() -> None:
    app_state = MockApplicationState()
    client = ElectrumSVClient(app_state)
    msg_box_external_id = "2y2A4zN1eLL7LHmNr8oFUbe4BD4IMr2jtBIT9EWTSb9xoTeZHY2n578dM83_C6m2GH52FJFgRavJBiNW73Lrvg=="
    msg_box_api_token = "_GaA5PlJ8WTF8OqhI6D6HAmlwYe8UbJgtRYZ2HxgdlAQ2H4KXNdcxtcztJ3C_wquz3bu1lAyjbWzjmkZMLGZfQ=="
    url = WS_URL_TEMPLATE_MSG_BOX.format(channelid=msg_box_external_id)
    while True:
        try:
            # HeaderSV
            # NOTE: remember to set:
            #   EXPOSE_HEADER_SV_APIS=1 &
            #   HEADER_SV_URL=http://localhost:8080 in .env file
            # await client.subscribe_to_headers_notifications(msg_box_api_token)

            # Peer Channels
            await client.subscribe_to_msg_box_notifications(url, msg_box_api_token)

        except HTTPClientError as e:
            break
        except (ConnectionRefusedError, ClientConnectorError):
            # print(f"Unable to connect to: {WS_URL_HEADERS} - retrying...")
            print(f"Unable to connect to: {url} - retrying...")
        except Exception as e:
            exc_type, exc_value, exc_tb = sys.exc_info()
            tb = traceback.TracebackException(exc_type, exc_value, exc_tb)
            print(''.join(tb.format_exception_only()))
            break


if __name__ == "__main__":
    asyncio.run(main())

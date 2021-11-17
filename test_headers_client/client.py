import asyncio
import logging
import sys

import traceback
import aiohttp
import bitcoinx
from aiohttp import ClientConnectorError

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 47124
BASE_URL = f"http://{SERVER_HOST}:{SERVER_PORT}"
WS_URL = "http://localhost:47124/api/v1/headers/websocket"


class MockApplicationState:

    def __init__(self) -> None:
        # some state
        pass


class WebsocketClient:
    def __init__(self, app_state: MockApplicationState) -> None:
        self.app_state = app_state
        self.logger = logging.getLogger("websocket-client")

    async def subscribe(self) -> None:
        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(WS_URL, timeout=5.0) as ws:
                print(f'Connected to {WS_URL}')

                async for msg in ws:
                    new_tip_hash = bitcoinx.hash_to_hex_str(bitcoinx.double_sha256(msg.data[0:80]))
                    new_tip_height = bitcoinx.unpack_be_uint32(msg.data[80:84])[0]
                    print('Message new chain tip hash: ', new_tip_hash, 'height: ', new_tip_height)
                    if msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                        break


# entrypoint to main event loop
async def main() -> None:
    app_state = MockApplicationState()
    client = WebsocketClient(app_state)
    while True:
        try:
            await client.subscribe()  # using aiohttp
        except (ConnectionRefusedError, ClientConnectorError):
            print(f"Unable to connect to: {WS_URL} - retrying...")
        except Exception as e:
            exc_type, exc_value, exc_tb = sys.exc_info()
            tb = traceback.TracebackException(exc_type, exc_value, exc_tb)
            print(''.join(tb.format_exception_only()))


if __name__ == "__main__":
    asyncio.run(main())

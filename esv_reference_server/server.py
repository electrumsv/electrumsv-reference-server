from pathlib import Path

import aiohttp
from aiohttp import web
import asyncio
import os
import logging
import queue
import threading
from typing import Dict, NoReturn

from .constants import SERVER_HOST, SERVER_PORT
from .handlers_ws import HeadersWebSocket, WSClient
from . import handlers
from .sqlite_db import SQLiteDatabase


MODULE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))

# Silence verbose logging
logger = logging.getLogger("server")

aiohttp_logger = logging.getLogger("aiohttp")
aiohttp_logger.setLevel(logging.WARNING)


class ApplicationState(object):

    def __init__(self, app: web.Application, loop: asyncio.AbstractEventLoop) -> None:
        self.logger = logging.getLogger('app_state')
        self.app = app
        self.loop = loop

        self.ws_clients: Dict[str, WSClient] = {}
        self.ws_clients_lock: threading.RLock = threading.RLock()
        self.ws_queue: queue.Queue[str] = queue.Queue()  # json only

        self.sqlite_db = SQLiteDatabase(MODULE_DIR.parent / 'esv_reference_server.db')

    def start_threads(self):
        threading.Thread(target=self.header_notifications_thread, daemon=True).start()

    def get_ws_clients(self) -> Dict[str, WSClient]:
        with self.ws_clients_lock:
            return self.ws_clients

    def add_ws_client(self, ws_client: WSClient):
        with self.ws_clients_lock:
            self.ws_clients[ws_client.ws_id] = ws_client

    def remove_ws_client(self, ws_client: WSClient) -> None:
        with self.ws_clients_lock:
            del self.ws_clients[ws_client.ws_id]

    def header_notifications_thread(self) -> None:
        """Emits any notifications from the queue to all connected websockets"""
        try:
            while self.app.is_alive:
                try:
                    json_msg = self.ws_queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                self.logger.debug(f"Got from ws_queue: {json_msg}")
                if not len(self.get_ws_clients()):
                    continue

                for ws_id, ws_client in self.get_ws_clients().items():
                    # self.logger.debug(f"Sending msg to ws_id: {ws_client.ws_id}")
                    asyncio.run_coroutine_threadsafe(ws_client.websocket.send_str(json_msg),
                        self.loop)
        except Exception:
            self.logger.exception("unexpected exception in header_notifications_thread")
        finally:
            self.logger.info("Closing push notifications thread")


async def client_session_ctx(app: web.Application) -> NoReturn:
    """
    Cleanup context async generator to create and properly close aiohttp ClientSession

    Ref.:

        > https://docs.aiohttp.org/en/stable/web_advanced.html#cleanup-context
        > https://docs.aiohttp.org/en/stable/web_advanced.html#aiohttp-web-signals
        > https://docs.aiohttp.org/en/stable/web_advanced.html#data-sharing-aka-no-singletons-please
    """
    logger.debug('Creating ClientSession')
    app['client_session'] = aiohttp.ClientSession()

    yield

    logger.debug('Closing ClientSession')
    await app['client_session'].close()


def get_aiohttp_app() -> web.Application:
    loop = asyncio.get_event_loop()
    app = web.Application()
    app.cleanup_ctx.append(client_session_ctx)
    app_state = ApplicationState(app, loop)

    # This is the standard aiohttp way of managing state within the handlers
    app['app_state'] = app_state
    app['ws_clients'] = app_state.ws_clients

    # Non-optional APIs
    app.add_routes([
        web.get("/", handlers.ping),
        web.get("/error", handlers.error),
        web.get("/api/v1/endpoints", handlers.get_endpoints_data),
        web.get("/api/v1/account", handlers.get_account)
    ])

    if os.getenv("EXPOSE_HEADER_SV_APIS") == "1":
        app.add_routes([
            web.get("/api/v1/headers", handlers.get_headers_by_height),
            web.get("/api/v1/chain/tips", handlers.get_chain_tips),
            web.view("/api/v1/headers/websocket", HeadersWebSocket),
        ])

    if os.getenv("EXPOSE_PEER_CHANNEL_APIS") == "1":
        pass  # TBD

    if os.getenv("EXPOSE_PAYMAIL_APIS") == "1":
        pass  # TBD

    return app


if __name__ == "__main__":
    app = get_aiohttp_app()
    web.run_app(app, host=SERVER_HOST, port=SERVER_PORT)

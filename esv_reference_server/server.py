from pathlib import Path

from aiohttp import web
import asyncio
import os
import logging
import queue
import threading
from typing import Dict

from electrumsv_sdk.utils import get_directory_name

from .handlers_ws import HeadersWebSocket, WSClient
from . import handlers
from .sqlite_db import SQLiteDatabase


SERVER_HOST = "127.0.0.1"
SERVER_PORT = 47124

COMPONENT_NAME = get_directory_name(__file__)
MODULE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))

# Silence verbose logging
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


def get_aiohttp_app() -> web.Application:
    loop = asyncio.get_event_loop()
    app = web.Application()
    app_state = ApplicationState(app, loop)

    # This is the standard aiohttp way of managing state within the handlers
    app['app_state'] = app_state
    app['ws_clients'] = app_state.ws_clients
    app.add_routes([
        web.get("/", handlers.ping),
        web.get("/error", handlers.error),
        web.get("/api/v1/headers", handlers.get_headers),
        web.view("/api/v1/headers/websocket", HeadersWebSocket),
    ])
    return app


if __name__ == "__main__":
    app = get_aiohttp_app()
    web.run_app(app, host=SERVER_HOST, port=SERVER_PORT)

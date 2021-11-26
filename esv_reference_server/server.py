"""
Copyright(c) 2021 Bitcoin Association.
Distributed under the Open BSV software license, see the accompanying file LICENSE
"""

import json
import time
from pathlib import Path

import aiohttp
import bitcoinx
import requests
from aiohttp import web
import asyncio
import os
import logging
import queue
import threading
from typing import AsyncIterator, Dict

from esv_reference_server.handlers_msg_box_ws import MsgBoxWebSocket
from esv_reference_server.msg_box.models import PushNotification
from esv_reference_server.msg_box.repositories import MsgBoxSQLiteRepository
from esv_reference_server.types import HeadersWSClient, MsgBoxWSClient
from .constants import Network, SERVER_HOST, SERVER_PORT
from .handlers_headers_ws import HeadersWebSocket

from .keys import create_regtest_server_keys, ServerKeys
from . import handlers
from esv_reference_server import msg_box
from .sqlite_db import SQLiteDatabase


MODULE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))

# Silence verbose logging
logger = logging.getLogger("server")

aiohttp_logger = logging.getLogger("aiohttp")
aiohttp_logger.setLevel(logging.WARNING)
requests_logger = logging.getLogger("urllib3")
requests_logger.setLevel(logging.WARNING)


class ApplicationState(object):
    server_keys: ServerKeys

    def __init__(self, app: web.Application, loop: asyncio.AbstractEventLoop,
            network: Network) -> None:
        self.logger = logging.getLogger('app_state')
        self.app = app
        self.loop = loop

        self.headers_ws_clients: Dict[str, HeadersWSClient] = {}
        self.headers_ws_clients_lock: threading.RLock = threading.RLock()
        self.headers_ws_queue: queue.Queue[str] = queue.Queue()  # json only

        self.msg_box_ws_clients: Dict[str, MsgBoxWSClient] = {}
        self.msg_box_ws_clients_lock: threading.RLock = threading.RLock()
        self.msg_box_new_msg_queue = queue.Queue()  # json only
        self.subscriptions_cache = {}  # msg_box_id: NotificationSubscription

        self.network = network
        self.sqlite_db = SQLiteDatabase(MODULE_DIR.parent / 'esv_reference_server.db')
        self.msg_box_repository = MsgBoxSQLiteRepository(self.sqlite_db)

        self.header_sv_url = os.getenv('HEADER_SV_URL')

    def start_threads(self):
        threading.Thread(target=self.message_box_notifications_thread, daemon=True).start()
        if os.getenv('EXPOSE_HEADER_SV_APIS', '0') == '1':
            threading.Thread(target=self.header_notifications_thread, daemon=True).start()

    # Headers Websocket Client Get/Add/Remove & Notify thread
    def get_ws_clients(self) -> Dict[str, HeadersWSClient]:
        with self.headers_ws_clients_lock:
            return self.headers_ws_clients

    def add_ws_client(self, ws_client: HeadersWSClient):
        with self.headers_ws_clients_lock:
            self.headers_ws_clients[ws_client.ws_id] = ws_client

    def remove_ws_client(self, ws_client: HeadersWSClient) -> None:
        with self.headers_ws_clients_lock:
            del self.headers_ws_clients[ws_client.ws_id]

    def header_notifications_thread(self) -> None:
        """Emits any notifications from the queue to all connected websockets"""
        try:
            current_best_hash = ""

            while self.app.is_alive:
                try:
                    url_to_fetch = f"{self.header_sv_url}/api/v1/chain/tips"
                    request_headers = {'Accept': 'application/json'}
                    result = requests.get(url_to_fetch, request_headers)
                    result.raise_for_status()
                    longest_chain_tip = None
                    for tip in result.json():
                        if tip['state'] == "LONGEST_CHAIN":
                            longest_chain_tip = tip

                    if current_best_hash != longest_chain_tip['header']['hash']:
                        self.logger.debug(f"Got new chain tip: {longest_chain_tip}")
                        current_best_hash = longest_chain_tip['header']['hash']
                        current_best_height = longest_chain_tip['height']
                    else:
                        time.sleep(2)
                        continue
                except requests.exceptions.ConnectionError as e:
                    logger.error(f"HeaderSV service is unavailable on {self.header_sv_url}")
                    # Any new websocket connections will be notified when HeaderSV is back online
                    current_best_hash = ""
                    continue
                except Exception as e:
                    logger.exception(e)
                    continue

                if not len(self.get_ws_clients()):
                    continue

                # Send new tip notification to all connected websocket clients
                for ws_id, ws_client in self.get_ws_clients().items():
                    self.logger.debug(f"Sending msg to ws_id: {ws_client.ws_id}")
                    url_to_fetch = f"{self.header_sv_url}/api/v1/chain/header/{current_best_hash}"

                    # Todo: this should actually be 'Accept' but HeaderSV uses 'Content-Type'
                    request_headers = {'Content-Type': 'application/octet-stream'}
                    result = requests.get(url_to_fetch, headers=request_headers)
                    result.raise_for_status()

                    response = bytearray()
                    response += result.content  # 80 byte header
                    response += bitcoinx.pack_be_uint32(current_best_height)
                    asyncio.run_coroutine_threadsafe(ws_client.websocket.send_bytes(response),
                        self.loop)
        except Exception:
            self.logger.exception("unexpected exception in header_notifications_thread")
        finally:
            self.logger.info("Closing push notifications thread")

    # Message Box Websocket Client Get/Add/Remove & Notify thread
    def get_msg_box_ws_clients(self) -> Dict[str, MsgBoxWSClient]:
        with self.msg_box_ws_clients_lock:
            return self.msg_box_ws_clients

    def add_msg_box_ws_client(self, ws_client: MsgBoxWSClient):
        with self.msg_box_ws_clients_lock:
            self.msg_box_ws_clients[ws_client.ws_id] = ws_client

    def remove_msg_box_ws_client(self, ws_client: MsgBoxWSClient) -> None:
        with self.msg_box_ws_clients_lock:
            del self.msg_box_ws_clients[ws_client.ws_id]

    def message_box_notifications_thread(self) -> None:
        """Emits any notifications from the queue to all connected websockets"""
        try:
            notification: PushNotification
            msg_box_api_token_id: int
            ws_client: MsgBoxWSClient
            while self.app.is_alive:
                try:
                    msg_box_api_token_id, notification = self.msg_box_new_msg_queue.get()
                except Exception as e:
                    logger.exception(e)
                    continue

                if not len(self.get_msg_box_ws_clients()):
                    continue

                # Send new message notifications to the relevant (and authenticated)
                # websocket client (based on msg_box_id)
                # Todo - for efficiency there needs to be a key: value cache to
                #  lookup the relevant clients - iterating over all clients is poor form...
                for ws_id, ws_client in self.get_msg_box_ws_clients().items():
                    self.logger.debug(f"Sending msg to ws_id: {ws_client.ws_id}")
                    if ws_client.msg_box_internal_id == notification.msg_box.id:
                        msg = json.dumps(notification.notification_new_message_text)

                    asyncio.run_coroutine_threadsafe(ws_client.websocket.send_json(notification.to_dict()),
                        self.loop)
        except Exception:
            self.logger.exception("unexpected exception in header_notifications_thread")
        finally:
            self.logger.info("Closing push notifications thread")


async def client_session_ctx(app: web.Application) -> AsyncIterator[None]:
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


def get_aiohttp_app(network: Network) -> web.Application:
    loop = asyncio.get_event_loop()
    app = web.Application()
    app.cleanup_ctx.append(client_session_ctx)
    app_state = ApplicationState(app, loop, network)

    if network == Network.REGTEST:
        # TODO(temporary-prototype-choice) Allow regtest key override or fallback to these?
        app_state.server_keys = create_regtest_server_keys()
    else:
        # TODO(temporary-prototype-choice) Have some way of finding the non-regtest keys.
        #     Error if they cannot be found.
        raise NotImplementedError

    # This is the standard aiohttp way of managing state within the handlers
    app['app_state'] = app_state
    app['headers_ws_clients'] = app_state.headers_ws_clients
    app['msg_box_ws_clients'] = app_state.msg_box_ws_clients

    # Non-optional APIs
    app.add_routes([
        web.get("/", handlers.ping),
        web.get("/error", handlers.error),
        web.get("/api/v1/endpoints", handlers.get_endpoints_data),

        # Payment Channel Account Management
        web.get("/api/v1/account", handlers.get_account),
        web.post("/api/v1/account/key", handlers.post_account_key),
        web.post("/api/v1/account/channel", handlers.post_account_channel),
        web.put("/api/v1/account/channel", handlers.put_account_channel_update),
        web.delete("/api/v1/account/channel", handlers.delete_account_channel),
        web.post("/api/v1/account/funding", handlers.post_account_funding),

        # Message Box Management (i.e. Custom Peer Channels implementation)
        web.get("/api/v1/channel/manage/list", msg_box.controller.list_channels),
        web.get("/api/v1/channel/manage/{channelid}", msg_box.controller.get_single_channel_details),
        web.post("/api/v1/channel/manage/{channelid}", msg_box.controller.update_single_channel_properties),
        web.delete("/api/v1/channel/manage/{channelid}", msg_box.controller.delete_channel),
        web.post("/api/v1/channel/manage", msg_box.controller.create_new_channel),
        web.get("/api/v1/channel/manage/{channelid}/api-token/{tokenid}", msg_box.controller.get_token_details),
        web.delete("/api/v1/channel/manage/{channelid}/api-token/{tokenid}", msg_box.controller.revoke_selected_token),
        web.get("/api/v1/channel/manage/{channelid}/api-token", msg_box.controller.get_list_of_tokens),
        web.post("/api/v1/channel/manage/{channelid}/api-token", msg_box.controller.create_new_token_for_channel),

        # Message Box Push / Pull API
        web.post("/api/v1/channel/{channelid}", msg_box.controller.write_message),
        # web.head is added automatically by web.get in aiohttp
        web.get("/api/v1/channel/{channelid}", msg_box.controller.get_messages, name='get_messages'),
        web.post("/api/v1/channel/{channelid}/{sequence}", msg_box.controller.mark_message_read_or_unread),
        web.delete("/api/v1/channel/{channelid}/{sequence}", msg_box.controller.delete_message),

        # Message Box Websocket API
        web.view("/api/v1/channel/{channelid}/notify", MsgBoxWebSocket),
    ])

    if os.getenv("EXPOSE_HEADER_SV_APIS") == "1":
        app.add_routes([
            web.get("/api/v1/header/{hash}", handlers.get_header),
            web.get("/api/v1/header", handlers.get_headers_by_height),
            web.get("/api/v1/chain/tips", handlers.get_chain_tips),
            web.view("/api/v1/headers/websocket", HeadersWebSocket),
        ])

    if os.getenv("EXPOSE_PAYMAIL_APIS") == "1":
        pass  # TBD

    return app


if __name__ == "__main__":
    app = get_aiohttp_app(Network.REGTEST)
    web.run_app(app, host=SERVER_HOST, port=SERVER_PORT)

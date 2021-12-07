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
from typing import AsyncIterator, Dict, Tuple, Optional

from aiohttp.web_app import Application

from esv_reference_server.handlers_headers import HeadersWebSocket
from esv_reference_server.msg_box.controller import MsgBoxWebSocket
from esv_reference_server.msg_box.models import PushNotification
from esv_reference_server.msg_box.repositories import MsgBoxSQLiteRepository
from esv_reference_server.types import HeadersWSClient, MsgBoxWSClient, Route, EndpointInfo
from .constants import Network, SERVER_HOST, SERVER_PORT

from .keys import create_regtest_server_keys, ServerKeys
from . import handlers, handlers_headers
from esv_reference_server import msg_box
from .sqlite_db import SQLiteDatabase

from aiohttp_swagger3 import SwaggerUiSettings, SwaggerFile, ValidatorError

MODULE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))

# Silence verbose logging
logger = logging.getLogger("server")

aiohttp_logger = logging.getLogger("aiohttp")
aiohttp_logger.setLevel(logging.WARNING)
requests_logger = logging.getLogger("urllib3")
requests_logger.setLevel(logging.WARNING)


class AiohttpApplication(web.Application):

    def __init__(self):
        super().__init__()
        self.is_alive: bool = False
        self.routes: list[Route] = []
        self.API_ROUTE_DEFS: dict[str, EndpointInfo] = {}


class ApplicationState(object):
    server_keys: ServerKeys

    def __init__(self, app: AiohttpApplication, loop: asyncio.AbstractEventLoop,
            network: Network, datastore_location: Path) -> None:
        self.logger = logging.getLogger('app_state')
        self.app = app
        self.loop = loop

        self.headers_ws_clients: Dict[str, HeadersWSClient] = {}
        self.headers_ws_clients_lock: threading.RLock = threading.RLock()
        self.headers_ws_queue: queue.Queue[str] = queue.Queue()  # json only

        self.msg_box_ws_clients: Dict[str, MsgBoxWSClient] = {}
        self.msg_box_ws_clients_lock: threading.RLock = threading.RLock()
        self.msg_box_new_msg_queue: queue.Queue = queue.Queue()  # json only

        self.network = network
        self.sqlite_db = SQLiteDatabase(datastore_location)
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

                    if not longest_chain_tip:  # should never happen
                        raise ValueError("No longest chain tip in response")

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

                    asyncio.run_coroutine_threadsafe(
                        ws_client.websocket.send_json(notification.to_dict()), self.loop)
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
    app['client_session'] = aiohttp.ClientSession()

    yield

    logger.debug('Closing ClientSession')
    await app['client_session'].close()


# Custom media handlers
async def application_json(request: web.Request) -> Tuple[Dict, bool]:
    try:
        return await request.json(), False
    except ValueError as e:
        raise ValidatorError(str(e))


async def application_octet_stream(request: web.Request) -> tuple[bytes, bool]:
    try:
        return await request.read(), True
    except ValueError as e:
        raise ValidatorError(str(e))


async def multipart_mixed(request: web.Request) \
        -> tuple[list[Optional[bytes]], bool]:
    try:
        reader = aiohttp.MultipartReader(request.headers, content=request.content)
        values = []
        async for part in reader:
            values.append(await part.next())
        return values, True
    except ValueError as e:
        raise ValidatorError(str(e))


def get_aiohttp_app(network: Network, datastore_location: Path, host: str = SERVER_HOST,
        port: int = SERVER_PORT) -> tuple[Application, str, int]:
    loop = asyncio.get_event_loop()
    app = AiohttpApplication()
    app.cleanup_ctx.append(client_session_ctx)
    app_state = ApplicationState(app, loop, network, datastore_location)

    if network == network.REGTEST:
        # TODO(temporary-prototype-choice) Allow regtest key override or fallback to these?
        REGTEST_VALID_ACCOUNT_TOKEN = os.getenv('REGTEST_VALID_ACCOUNT_TOKEN',
                                                "t80Dp_dIk1kqkHK3P9R5cpDf67JfmNixNscexEYG0_xa"
                                                "CbYXKGNm4V_2HKr68ES5bytZ8F19IS0XbJlq41accQ==")
        REGTEST_CLIENT_PRIVATE_KEY = os.getenv('REGTEST_CLIENT_PRIVATE_KEY',
                                               '720f1987db69efa562b3dabd78e51f19'
                                               'bd8da76c70ad839b72b939f4071b144b')
        client_priv_key = bitcoinx.PrivateKey.from_hex(REGTEST_CLIENT_PRIVATE_KEY)
        client_pub_key: bitcoinx.PublicKey = client_priv_key.public_key
        account_id, api_key = app_state.sqlite_db.create_account(
            client_pub_key.to_bytes(), forced_api_key=REGTEST_VALID_ACCOUNT_TOKEN)
        logger.debug(f"Got RegTest account_id: {account_id}, api_key: {api_key}")
        app_state.server_keys = create_regtest_server_keys()
    else:
        # TODO(temporary-prototype-choice) Have some way of finding the non-regtest keys.
        #     Error if they cannot be found.
        raise NotImplementedError

    # This is the standard aiohttp way of managing state within the handlers
    app['app_state'] = app_state
    app['headers_ws_clients'] = app_state.headers_ws_clients
    app['msg_box_ws_clients'] = app_state.msg_box_ws_clients

    swagger = SwaggerFile(app, spec_file=str(MODULE_DIR.parent.joinpath("swagger.yaml")),
        swagger_ui_settings=SwaggerUiSettings(path="/api/v1/docs"))
    swagger.register_media_type_handler("application/json", application_json)
    swagger.register_media_type_handler("application/octet-stream", application_octet_stream)
    swagger.register_media_type_handler("multipart/mixed", multipart_mixed)

    # Non-optional APIs
    # cache app.routes to assist with keeping unit tests up-to-date
    # 'auth_required' information is only used by unit-testing at the moment to assert that auth
    # checks are being done
    app.routes = [
        Route(web.get("/",
                      handlers.ping), False),
        Route(web.get("/api/v1/endpoints",
                      handlers.get_endpoints_data), False),

        # Payment Channel Account Management
        Route(web.get("/api/v1/account",
                      handlers.get_account), True),
        Route(web.post("/api/v1/account/key",
                       handlers.post_account_key), True),
        Route(web.post("/api/v1/account/channel",
                       handlers.post_account_channel), True),
        Route(web.put("/api/v1/account/channel",
                      handlers.put_account_channel_update), True),
        Route(web.delete("/api/v1/account/channel",
                         handlers.delete_account_channel), True),
        Route(web.post("/api/v1/account/funding",
                       handlers.post_account_funding), True),

        # Message Box Management (i.e. Custom Peer Channels implementation)
        Route(web.get("/api/v1/channel/manage/list",
                      msg_box.controller.list_channels, allow_head=False), True),
        Route(web.get("/api/v1/channel/manage/{channelid}",
                      msg_box.controller.get_single_channel_details), True),
        Route(web.post("/api/v1/channel/manage/{channelid}",
                       msg_box.controller.update_single_channel_properties), True),
        Route(web.delete("/api/v1/channel/manage/{channelid}",
                         msg_box.controller.delete_channel), True),
        Route(web.post("/api/v1/channel/manage",
                       msg_box.controller.create_new_channel), True),
        Route(web.get("/api/v1/channel/manage/{channelid}/api-token/{tokenid}",
                      msg_box.controller.get_token_details), True),
        Route(web.delete("/api/v1/channel/manage/{channelid}/api-token/{tokenid}",
                         msg_box.controller.revoke_selected_token), True),
        Route(web.get("/api/v1/channel/manage/{channelid}/api-token",
                      msg_box.controller.get_list_of_tokens), True),
        Route(web.post("/api/v1/channel/manage/{channelid}/api-token",
                       msg_box.controller.create_new_token_for_channel), True),

        # Message Box Push / Pull API
        Route(web.post("/api/v1/channel/{channelid}",
                       msg_box.controller.write_message), True),
        # web.head is added automatically by web.get in aiohttp
        Route(web.get("/api/v1/channel/{channelid}",
                      msg_box.controller.get_messages), True),
        Route(web.post("/api/v1/channel/{channelid}/{sequence}",
                       msg_box.controller.mark_message_read_or_unread), True),
        Route(web.delete("/api/v1/channel/{channelid}/{sequence}",
                         msg_box.controller.delete_message), True),

        # Message Box Websocket API
        Route(web.view("/api/v1/channel/{channelid}/notify",
                       MsgBoxWebSocket), True),
    ]
    if os.getenv("EXPOSE_HEADER_SV_APIS") == "1":
        app.routes.extend([
            Route(web.get("/api/v1/headers/by-height",
                          handlers_headers.get_headers_by_height), True),
            Route(web.get("/api/v1/headers/{hash}",
                          handlers_headers.get_header), False),
            Route(web.get("/api/v1/chain/tips",
                          handlers_headers.get_chain_tips), False),
            Route(web.view("/api/v1/chain/tips/websocket",
                           HeadersWebSocket), False),
            Route(web.get("/api/v1/network/peers",
                          handlers_headers.get_peers), False),
        ])

    if os.getenv("EXPOSE_PAYMAIL_APIS") == "1":
        pass  # TBD

    for route_def, auth_required in app.routes:
        swagger.add_routes([route_def])

    BASE_URL = f"http://{host}:{port}"
    app.host = host
    app.port = port
    app.API_ROUTE_DEFS = {}
    for route in app.routes:
        route_def = route.aiohttp_route_def
        auth_required = route.auth_required  # Bearer Token
        app.API_ROUTE_DEFS[route_def.handler.__name__] = EndpointInfo(route_def.method,
            BASE_URL + route_def.path, auth_required)

    return app, host, port


if __name__ == "__main__":
    DEFAULT_DATASTORE_LOCATION = MODULE_DIR.parent / 'esv_reference_server.sqlite'
    datastore_location = Path(os.getenv('DATASTORE_LOCATION', DEFAULT_DATASTORE_LOCATION))
    app, host, port = get_aiohttp_app(Network.REGTEST, datastore_location)
    web.run_app(app, host=SERVER_HOST, port=SERVER_PORT)

"""
Copyright(c) 2021 Bitcoin Association.
Distributed under the Open BSV software license, see the accompanying file LICENSE
"""

from collections import defaultdict
import json
import struct
from pathlib import Path

import aiohttp
import bitcoinx
from aiohttp import web
import asyncio
import os
import logging
import threading
from typing import Any, AsyncIterator, Optional

from aiohttp.web_app import Application

from .constants import ACCOUNT_MESSAGE_NAMES, Network, SERVER_HOST, SERVER_PORT
from . import handlers, handlers_headers, handlers_indexer
from .indexer_support import maintain_indexer_connection, unregister_unwanted_spent_outputs
from .keys import create_regtest_server_keys, ServerKeys
from . import msg_box
from .msg_box.controller import MsgBoxWebSocket
from .msg_box.repositories import MsgBoxSQLiteRepository
from .sqlite_db import SQLiteDatabase
from .types import AccountMessage, AccountWebsocketState, EndpointInfo, GeneralNotification, \
    HeadersWSClient, MsgBoxWSClient, Outpoint, PushNotification, Route
from .utils import pack_account_message_bytes
from .websock import GeneralWebSocket

try:
    from aiohttp_swagger3 import SwaggerUiSettings, SwaggerFile, ValidatorError
except ModuleNotFoundError:
    found_swagger = False
else:
    found_swagger = True

MODULE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))

# Silence verbose logging
logger = logging.getLogger("server")

aiohttp_logger = logging.getLogger("aiohttp")
aiohttp_logger.setLevel(logging.WARNING)
requests_logger = logging.getLogger("urllib3")
requests_logger.setLevel(logging.WARNING)


class AiohttpApplication(web.Application):

    def __init__(self) -> None:
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

        self._account_websocket_state: dict[str, AccountWebsocketState] = {}
        self._account_websocket_id_by_account_id: dict[int, str] = {}  # account_id: ws_id
        self._account_websocket_state_lock: threading.RLock = threading.RLock()
        self.account_message_queue: asyncio.Queue[AccountMessage] = asyncio.Queue()

        self.headers_ws_clients: dict[str, HeadersWSClient] = {}
        self.headers_ws_clients_lock: threading.RLock = threading.RLock()

        self.msg_box_ws_clients: dict[str, MsgBoxWSClient] = {}
        self.msg_box_ws_clients_map: dict[int, set[str]] = {}  # msg_box_id: ws_ids
        self.msg_box_ws_clients_lock: threading.RLock = threading.RLock()
        self.msg_box_new_msg_queue: asyncio.Queue[tuple[int, PushNotification]] = asyncio.Queue()

        self.network = network
        self.sqlite_db = SQLiteDatabase(datastore_location)
        self.msg_box_repository = MsgBoxSQLiteRepository(self.sqlite_db)

        self.header_sv_url = os.getenv('HEADER_SV_URL')
        self.aiohttp_session: Optional[aiohttp.ClientSession] = None

        # Indexer-related state.
        self._indexer_task: Optional[asyncio.Task[None]] = None
        self.indexer_url = os.getenv('INDEXER_URL')
        self._output_spend_counts: dict[Outpoint, int] = defaultdict(int)

        # TODO(1.4.0) Accounts. Until we have free quota accounts we need a way to
        #     access the server as if we were doing so with an account. This should be removed
        #     when we have proper account usage in ESV.
        self.temporary_account_id: Optional[int] = None

    def start_tasks(self) -> None:
        asyncio.create_task(self._account_notifications_task())
        asyncio.create_task(self.message_box_notifications_task())
        if os.getenv('EXPOSE_HEADER_SV_APIS', '0') == '1':
            asyncio.create_task(self.header_notifications_task())
        if os.getenv("EXPOSE_INDEXER_APIS", "0") == "1":
            self._indexer_task = asyncio.create_task(maintain_indexer_connection(self))

    def stop_tasks(self) -> None:
        if self._indexer_task is not None:
            self._indexer_task.cancel()

    # Headers Websocket Client Get/Add/Remove & Notify thread
    def get_headers_ws_clients(self) -> dict[str, HeadersWSClient]:
        with self.headers_ws_clients_lock:
            return self.headers_ws_clients

    def add_headers_ws_client(self, ws_client: HeadersWSClient) -> None:
        with self.headers_ws_clients_lock:
            self.headers_ws_clients[ws_client.ws_id] = ws_client

    def remove_headers_ws_client(self, ws_id: str) -> None:
        with self.headers_ws_clients_lock:
            del self.headers_ws_clients[ws_id]

    async def _get_aiohttp_session(self) -> aiohttp.ClientSession:
        if not self.aiohttp_session:
            self.aiohttp_session = aiohttp.ClientSession()
        return self.aiohttp_session

    async def close_aiohttp_session(self) -> None:
        if self.aiohttp_session:
            await self.aiohttp_session.close()

    async def header_notifications_task(self) -> None:
        """Emits any notifications from the queue to all connected websockets"""
        try:
            session = await self._get_aiohttp_session()
            current_best_hash = ""

            while self.app.is_alive:
                try:
                    url_to_fetch = f"{self.header_sv_url}/api/v1/chain/tips"
                    request_headers = {'Accept': 'application/json'}
                    async with session.post(url_to_fetch, headers=request_headers) as resp:
                        assert resp.status == 200, resp.reason
                        result = await resp.json()

                    longest_chain_tip = None
                    for tip in result:
                        if tip['state'] == "LONGEST_CHAIN":
                            longest_chain_tip = tip

                    if not longest_chain_tip:  # should never happen
                        raise ValueError("No longest chain tip in response")

                    if current_best_hash != longest_chain_tip['header']['hash']:
                        self.logger.debug(f"Got new chain tip: {longest_chain_tip}")
                        current_best_hash = longest_chain_tip['header']['hash']
                        current_best_height = longest_chain_tip['height']
                    else:
                        await asyncio.sleep(1)
                        continue
                except aiohttp.ClientConnectorError as e:
                    # logger.error(f"HeaderSV service is unavailable on {self.header_sv_url}")
                    # Any new websocket connections will be notified when HeaderSV is back online
                    current_best_hash = ""
                    await asyncio.sleep(1)
                    continue
                except Exception as e:
                    logger.exception(e)
                    await asyncio.sleep(1)
                    continue

                if not len(self.get_headers_ws_clients()) and \
                        not len(self.get_account_websockets()):
                    continue

                url_to_fetch = f"{self.header_sv_url}/api/v1/chain/header/{current_best_hash}"
                request_headers = {'Accept': 'application/octet-stream'}
                async with await session.post(url_to_fetch, headers=request_headers) as resp:
                    assert resp.status == 200, resp.reason
                    raw_header = await resp.read()

                tip_notification = raw_header + struct.pack('<I', current_best_height)

                # Send new tip notification to all connected websocket clients
                for ws_id, ws_client in self.get_headers_ws_clients().items():
                    try:
                        self.logger.debug(f"Sending msg to header websocket client "
                                          f"ws_id: {ws_client.ws_id}")
                        await ws_client.websocket.send_bytes(tip_notification)
                    except ConnectionResetError:
                        self.logger.error(f"Websocket disconnected")

                # Send new tip notification to all connected websocket clients
                for ws_id, ws_client_general in self.get_account_websockets().items():
                    try:
                        self.logger.debug(f"Sending msg to general websocket client "
                                          f"ws_id: {ws_client_general.ws_id}")
                        await ws_client_general.websocket.send_json(
                            GeneralNotification(message_type="bsvapi.headers.tip", result=result))
                    except ConnectionResetError:
                        self.logger.error(f"Websocket disconnected")
        except Exception:
            self.logger.exception("unexpected exception in header_notifications_thread")
        finally:
            self.logger.info("Closing push notifications thread")

    # Message Box Websocket Client Get/Add/Remove & Notify thread
    def get_msg_box_ws_clients(self) -> dict[str, MsgBoxWSClient]:
        with self.msg_box_ws_clients_lock:
            return self.msg_box_ws_clients

    def get_msg_box_ws_clients_by_channel_id(self, msg_box_internal_id: int) \
            -> list[MsgBoxWSClient]:
        with self.msg_box_ws_clients_lock:
            ws_ids = self.msg_box_ws_clients_map[msg_box_internal_id]
            ws_clients = []
            for ws_id in ws_ids:
                ws_clients.append(self.msg_box_ws_clients[ws_id])
            return ws_clients

    def add_msg_box_ws_client(self, ws_client: MsgBoxWSClient) -> None:
        """Creates a two-way mapping for fast lookups"""
        with self.msg_box_ws_clients_lock:
            self.msg_box_ws_clients[ws_client.ws_id] = ws_client
            if self.msg_box_ws_clients_map.get(ws_client.msg_box_internal_id) is None:
                self.msg_box_ws_clients_map[ws_client.msg_box_internal_id] = set()
            self.msg_box_ws_clients_map[ws_client.msg_box_internal_id].add(ws_client.ws_id)

    def remove_msg_box_ws_client(self, ws_id: str) -> None:
        with self.msg_box_ws_clients_lock:
            msg_box_internal_id = self.msg_box_ws_clients[ws_id].msg_box_internal_id
            del self.msg_box_ws_clients[ws_id]
            self.msg_box_ws_clients_map[msg_box_internal_id].remove(ws_id)
            if len(self.msg_box_ws_clients_map[msg_box_internal_id]) == 0:
                del self.msg_box_ws_clients_map[msg_box_internal_id]

    async def message_box_notifications_task(self) -> None:
        """Emits any notifications from the queue to all connected websockets"""
        try:
            notification: PushNotification
            msg_box_api_token_id: int
            ws_client: MsgBoxWSClient
            while self.app.is_alive:
                try:
                    msg_box_api_token_id, notification = await self.msg_box_new_msg_queue.get()
                    self.logger.debug(f"Got peer channel notification for channel_id: "
                                      f"{msg_box_api_token_id}")
                except Exception as e:
                    logger.exception(e)
                    continue

                if not len(self.get_msg_box_ws_clients()):
                    continue

                # Send new message notifications to the relevant (and authenticated)
                # websocket client (based on msg_box_id)
                # Todo - key: value cache to lookup the relevant client
                msg_box = notification['msg_box']
                ws_clients = self.get_msg_box_ws_clients_by_channel_id(msg_box.id)
                for ws_client in ws_clients:
                    self.logger.debug(f"Sending msg to ws_id: {ws_client.ws_id}")
                    if ws_client.msg_box_internal_id == notification['msg_box'].id:
                        try:
                            msg = json.dumps(notification['notification'])
                            await ws_client.websocket.send_str(data=msg)
                        except ConnectionResetError as e:
                            self.logger.error(f"Websocket disconnected")

        except Exception:
            self.logger.exception("unexpected exception in message_box_notifications_task")
        finally:
            self.logger.info("Closing push notifications thread")

    # General Websocket Client Get/Add/Remove & Notify thread
    def get_account_websockets(self) -> dict[str, AccountWebsocketState]:
        with self._account_websocket_state_lock:
            return self._account_websocket_state

    def get_websocket_state_for_account_id(self, account_id: int) \
            -> Optional[AccountWebsocketState]:
        with self._account_websocket_state_lock:
            websocket_id = self._account_websocket_id_by_account_id.get(account_id)
            if websocket_id:
                return self._account_websocket_state[websocket_id]
            return None

    def setup_account_websocket(self, websocket_state: AccountWebsocketState) -> None:
        """
        Track a newly connected websocket for a given account.
        """
        with self._account_websocket_state_lock:
            self._account_websocket_state[websocket_state.ws_id] = websocket_state
            self._account_websocket_id_by_account_id[websocket_state.account_id] \
                = websocket_state.ws_id

    def teardown_account_websocket(self, websocket_id: str) -> None:
        """
        Stop tracking a now disconnected websocket for a given account.
        """
        with self._account_websocket_state_lock:
            account_id = self._account_websocket_state[websocket_id].account_id
            del self._account_websocket_state[websocket_id]
            del self._account_websocket_id_by_account_id[account_id]

            outpoints_to_unregister: set[Outpoint] = set()
            websocket_state = self.get_websocket_state_for_account_id(account_id)
            if websocket_state is not None:
                for outpoint in websocket_state.spent_output_registrations:
                    if self._output_spend_counts[outpoint] > 1:
                        self._output_spend_counts[outpoint] -= 1
                    else:
                        del self._output_spend_counts[outpoint]
                        outpoints_to_unregister.add(outpoint)

            if outpoints_to_unregister:
                # TODO(1.4.0) Indexer. Consider any race conditions where a user establishes a new
                #     connection and the old indexer registrations are removed after the new ones
                #     are put in place.
                asyncio.create_task(
                    unregister_unwanted_spent_outputs(self, account_id, outpoints_to_unregister))

    async def _account_notifications_task(self) -> None:
        """
        Serialise and send outgoing account-related notifications.
        """
        while self.app.is_alive:
            account_id, message_kind, payload = await self.account_message_queue.get()
            self.logger.debug("Got account notification, account_id=%d", account_id)

            websocket_state = self.get_websocket_state_for_account_id(account_id)
            if websocket_state is None:
                self.logger.debug(
                    "No websocket, dropped message, message_kind=%s, account_id=%d",
                    message_kind, account_id)
                continue

            if websocket_state.accept_type == "application/json":
                message_kind_name = ACCOUNT_MESSAGE_NAMES[message_kind]
                # TODO(1.4.0) JSON support. We might consider unpacking this for JSON into
                #     some dictionary structure rather than just giving them the hex.
                if isinstance(payload, bytes): # spent output notification
                    payload = payload.hex()
                json_object = GeneralNotification(message_type=message_kind_name, result=payload)
                try:
                    await websocket_state.websocket.send_str(data=json.dumps(json_object))
                except ConnectionResetError:
                    self.logger.debug(
                        "Dropped message for disconnected text websocket, message_kind=%s, "
                        "account_id=%d", message_kind, account_id)
            else:
                message_bytes = pack_account_message_bytes(message_kind, payload)
                try:
                    await websocket_state.websocket.send_bytes(data=message_bytes)
                except ConnectionResetError:
                    self.logger.debug(
                        "Dropped message for disconnected binary websocket, message_kind=%s, "
                        "account_id=%d", message_kind, account_id)

        self.logger.info("exiting push notifications thread")


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


if found_swagger:
    # Custom media handlers
    async def application_json(request: web.Request) -> tuple[dict[Any, Any], bool]:
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
        # TODO(1.4.0) Accounts. Until we have free quota accounts we need a way to
        #     access the server as if we were doing so with an account. This should be removed
        #     when we have proper account usage in ESV.
        app_state.temporary_account_id = account_id
        app_state.server_keys = create_regtest_server_keys()
    else:
        # TODO(temporary-prototype-choice) Have some way of finding the non-regtest keys.
        #     Error if they cannot be found.
        raise NotImplementedError

    # This is the standard aiohttp way of managing state within the handlers
    app['app_state'] = app_state
    app['headers_ws_clients'] = app_state.headers_ws_clients
    app['msg_box_ws_clients'] = app_state.msg_box_ws_clients
    app['_account_websocket_state'] = app_state._account_websocket_state

    if found_swagger:
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

        # General-Purpose consolidated Websocket - Requires master bearer token
        Route(web.view("/api/v1/web-socket", GeneralWebSocket), True)
    ]
    if os.getenv("EXPOSE_HEADER_SV_APIS") == "1":
        app.routes.extend([
            Route(web.view("/api/v1/headers/tips/websocket",
                           handlers_headers.HeadersWebSocket), False),
            Route(web.get("/api/v1/headers/tips",
                          handlers_headers.get_chain_tips), False),
            Route(web.get("/api/v1/headers/by-height",
                          handlers_headers.get_headers_by_height), True),
            Route(web.get("/api/v1/headers/{hash}",
                          handlers_headers.get_header), False),
            Route(web.get("/api/v1/network/peers",
                          handlers_headers.get_peers), False),
        ])

    if os.getenv("EXPOSE_PAYMAIL_APIS") == "1":
        pass  # TBD

    if os.getenv("EXPOSE_INDEXER_APIS") == "1":
        app.routes.extend([
            Route(web.post("/api/v1/restoration/search",
                handlers_indexer.indexer_post_pushdata_filter_matches), False),
            Route(web.get("/api/v1/transaction/{txid}",
                handlers_indexer.indexer_get_transaction), False),
            Route(web.get("/api/v1/merkle-proof/{txid}",
                handlers_indexer.indexer_get_merkle_proof), False),
            Route(web.post("/api/v1/output-spend",
                handlers_indexer.indexer_post_output_spends), False),
            Route(web.post("/api/v1/output-spend/notifications",
                handlers_indexer.indexer_post_output_spend_notifications), False),
        ])

    if found_swagger:
        for route_def, auth_required in app.routes:
            swagger.add_routes([route_def])
    else:
        app.add_routes([ v[0] for v in app.routes ])

    app.found_swagger = found_swagger

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

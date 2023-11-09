# Copyright(c) 2022 Bitcoin Association.
# Distributed under the Open BSV software license, see the accompanying file LICENSE

from __future__ import annotations
import asyncio, logging, os, struct, threading, time, weakref
from collections import defaultdict
from http import HTTPStatus
from pathlib import Path

import aiohttp
from aiohttp import web
from electrumsv_database.sqlite import DatabaseContext

try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.10.0 builds and bundled version of 3.35.5.
    import sqlite3


from .constants import ACCOUNT_MESSAGE_NAMES, Network, OutboundDataFlag
from .indexer_support import maintain_indexer_connection_async, unregister_unwanted_spent_outputs
from .keys import create_regtest_server_keys, ServerKeys, get_server_keys
from .msg_box.repositories import MsgBoxSQLiteRepository
from . import sqlite_db
from .types import AccountMessage, AccountWebsocketState, GeneralNotification, \
    HeadersWSClient, MsgBoxWSClient, NotificationJsonData, OutboundDataLogRow, \
    OutboundDataPendingRow, Outpoint
from .utils import pack_account_message_bytes


logger = logging.getLogger("app-state")


# NOTE(rt12) Futures generally swallow exceptions and propagate them to the callbacks. If there
# are no callbacks the exceptions just get swallowed. Terrible design flaw, they should log the
# exceptions if there are no callbacks as ERROR level.
def asyncio_task_callback(future: asyncio.Task[None]) -> None:
    if future.cancelled():
        return
    future.result()


class ApplicationState(object):
    server_keys: ServerKeys

    # This application should always be present.
    external_application: web.Application
    # This application may be present if there is need for it.
    internal_application: web.Application|None = None

    singleton_reference: weakref.ReferenceType[ApplicationState]|None = None
    singleton_event = threading.Event()

    def __init__(self, network: Network, datastore_location: Path, internal_host: str,
            internal_port: int, external_host: str, external_port: int) -> None:
        self.logger = logging.getLogger('app-state')

        assert ApplicationState.singleton_reference is None
        ApplicationState.singleton_reference = weakref.ref(self)

        self._internal_server_started = False
        self._external_server_started = False

        self.internal_host = internal_host
        self.internal_port = internal_port
        self.external_host = external_host
        self.external_port = external_port
        self.network = network

        if network == network.REGTEST:
            self.server_keys = create_regtest_server_keys()
        else:
            self.server_keys = get_server_keys()

        self._exit_event = asyncio.Event()
        self.aiohttp_session = aiohttp.ClientSession()

        self._account_websocket_state: dict[str, AccountWebsocketState] = {}
        self._account_websocket_id_by_account_id: dict[int, str] = {}  # account_id: ws_id
        self._account_websocket_state_lock: threading.RLock = threading.RLock()
        self.account_message_queue: asyncio.Queue[AccountMessage] = asyncio.Queue()

        self.headers_ws_clients: dict[str, HeadersWSClient] = {}
        self.headers_ws_clients_lock: threading.RLock = threading.RLock()

        self.msg_box_ws_clients: dict[str, MsgBoxWSClient] = {}
        self.ws_clients_by_messagebox_id: dict[int, set[str]] = {}  # msg_box_id: ws_ids
        self.msg_box_ws_clients_lock: threading.RLock = threading.RLock()
        self.msgbox_notification_queue: asyncio.Queue[tuple[int, NotificationJsonData]] \
            = asyncio.Queue()

        def _setup_database(db: sqlite3.Connection|None=None) -> None:
            if int(os.getenv('REFERENCE_SERVER_RESET', "0")):
                self.logger.info("Dropping database tables")
                self.msg_box_repository.drop_tables(db)
                sqlite_db.delete_all_tables(db)
            self.logger.info("Creating any missing database tables")
            sqlite_db.setup(db)
            self.msg_box_repository.create_tables(db)

        self.database_context = DatabaseContext(str(datastore_location), write_warn_ms=10)
        self.msg_box_repository = MsgBoxSQLiteRepository(self.database_context)
        self.database_context.run_in_thread(_setup_database)

        self.header_sv_url = os.getenv('HEADER_SV_URL')

        self._account_notifications_task: asyncio.Task[None]|None = None
        self._message_box_notifications_task: asyncio.Task[None]|None = None
        self._header_notifications_task: asyncio.Task[None]|None = None
        self._outbound_data_delivery_future: asyncio.Future[None]|None = None

        # Indexer-related state.
        self._indexer_task: asyncio.Task[None]|None = None
        self.indexer_url = os.getenv('INDEXER_URL')
        self.indexer_is_connected = False
        self._output_spend_counts: dict[Outpoint, int] = defaultdict(int)

    async def setup_async(self, internal_application: web.Application|None,
            external_application: web.Application) -> None:
        self.internal_application = internal_application
        self.external_application = external_application

        self._account_notifications_task = asyncio.create_task(
            self._manage_account_notifications_async())
        self._message_box_notifications_task = asyncio.create_task(
            self._manage_message_box_notifications_async())
        if os.getenv('EXPOSE_HEADER_SV_APIS', '0') == '1':
            self._header_notification_task = asyncio.create_task(
                self._header_notifications_task_async())
        if os.getenv("EXPOSE_INDEXER_APIS", "0") == "1":
            self._indexer_task = asyncio.create_task(maintain_indexer_connection_async(self))

            if os.getenv("ENABLE_OUTBOUND_DATA_DELIVERY", "0") == "1":
                self._outbound_data_delivery_future = self._create_outbound_delivery_task()

    async def teardown_async(self) -> None:
        self._exit_event.set()

        if self._account_notifications_task is not None:
            self._account_notifications_task.cancel()
        if self._message_box_notifications_task is not None:
            self._message_box_notifications_task.cancel()
        if self._header_notifications_task is not None:
            self._header_notifications_task.cancel()
        if self._indexer_task is not None:
            self._indexer_task.cancel()
        if self._outbound_data_delivery_future is not None:
            self._outbound_data_delivery_future.cancel()

        self.logger.info("Closing HTTP sessions")
        await self.aiohttp_session.close()

        # In theory this will block additional writes being put in place and empty the existing
        # queue. But the write dispatcher will block this thread, the async thread, while it
        # does this. That means that the tasks above may not get a chance to cleanly exit, and
        # remember explicit `cancel` calls schedule the task being cancelled and we do not yield
        # the async thread allowing further tasks to happen.
        # TODO(1.4.0) Clean exit. Async tasks may need to do writes on exit. Look into this.
        self.logger.info("Closing database")
        self.database_context.close()

        ApplicationState.singleton_reference = None

    async def wait_for_exit_async(self, internal: bool=False, external: bool=False) -> None:
        startup_complete = False
        if internal:
            self._internal_server_started = True
            startup_complete = self._external_server_started
        elif external:
            self._external_server_started = True
            if self.internal_application is None:
                startup_complete = True
            else:
                startup_complete = self._internal_server_started
        if startup_complete:
            self.singleton_event.set()
        await self._exit_event.wait()

    def _create_outbound_delivery_task(self) -> asyncio.Task[None]:
        task = asyncio.create_task(self._attempt_outbound_data_delivery_task())
        task.add_done_callback(asyncio_task_callback)
        return task

    async def _attempt_outbound_data_delivery_task(self) -> None:
        """
        Non-blocking delivery of new tip filter notifications.
        """
        self.logger.debug("Starting outbound data delivery task")
        MAXIMUM_DELAY = 120.0
        while True:
            # No point in trying if there is no reference server connected.
            next_check_delay = MAXIMUM_DELAY
            rows = sqlite_db.read_pending_outbound_datas(self.database_context,
                OutboundDataFlag.NONE, OutboundDataFlag.DISPATCHED_SUCCESSFULLY)
            current_rows = list[OutboundDataPendingRow]()
            if len(rows) > 0:
                current_time = time.time()
                for row in rows:
                    if row.date_created + MAXIMUM_DELAY > current_time:
                        next_check_delay = (row.date_created + MAXIMUM_DELAY) - current_time
                        break
                    current_rows.append(row)

            if len(current_rows) > 0:
                self.logger.debug("Outbound data delivery of %d entries, next delay will be %0.2f",
                    len(current_rows), next_check_delay)

            date_created = int(time.time())
            log_creation_rows = list[OutboundDataLogRow]()
            flag_data_updates = list[tuple[OutboundDataFlag, int]]()
            for row in current_rows:
                assert row.outbound_data_id is not None
                if row.tip_filter_callback_url is None:
                    log_creation_rows.append(OutboundDataLogRow(
                        row.account_id, row.outbound_data_id,
                        row.outbound_data_flags | OutboundDataFlag.DISPATCH_NO_CALLBACK,
                        None, None, date_created))
                else:
                    url = row.tip_filter_callback_url
                    headers = {
                        "Content-Type":     row.content_type,
                    }
                    if row.tip_filter_callback_token is not None:
                        headers["Authorization"] = row.tip_filter_callback_token
                    batch_text = row.outbound_data.decode("utf-8")
                    updated_flags = row.outbound_data_flags
                    try:
                        async with self.aiohttp_session.post(url, headers=headers,
                                data=batch_text) as response:
                            if response.status == HTTPStatus.OK:
                                self.logger.debug("Posted outbound data for account %d to '%s' "+
                                    "status=%s, reason=%s", row.account_id, url, response.status,
                                    response.reason)
                                updated_flags |= OutboundDataFlag.DISPATCHED_SUCCESSFULLY
                                flag_data_updates.append((updated_flags, row.outbound_data_id))
                                log_creation_rows.append(OutboundDataLogRow(
                                    row.account_id, row.outbound_data_id, row.outbound_data_flags,
                                    response.status, response.reason, date_created))
                            else:
                                self.logger.error("Failed to post outbound data for account %d "+
                                    "to '%s' status=%s, reason=%s", row.account_id, url,
                                    response.status, response.reason)
                                log_creation_rows.append(OutboundDataLogRow(
                                    row.account_id, row.outbound_data_id, row.outbound_data_flags,
                                    response.status, response.reason, date_created))
                    except aiohttp.ClientError:
                        self.logger.exception("Errored posting outbound data for account %d to "
                            "'%s'", row.account_id, url)
                        # We should work out what exceptions are normal (e.g. invalid URL) and
                        # just add a flag for those. The rest of the exceptions should be in the
                        # log (or redirected to some sys admin notification mechanism).
                        log_creation_rows.append(OutboundDataLogRow(
                            row.account_id, row.outbound_data_id,
                            row.outbound_data_flags | OutboundDataFlag.DISPATCH_EXCEPTION,
                            None, None, date_created))

            if len(log_creation_rows) > 0:
                await self.database_context.run_in_thread_async(
                    sqlite_db.create_outbound_data_logs_write, log_creation_rows)

            if len(flag_data_updates) > 0:
                await self.database_context.run_in_thread_async(
                    sqlite_db.update_outbound_data_flags_write, flag_data_updates)

            await asyncio.sleep(next_check_delay)

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

    def get_aiohttp_session(self) -> aiohttp.ClientSession:
        return self.aiohttp_session

    async def _header_notifications_task_async(self) -> None:
        """Emits any notifications from the queue to all connected websockets"""
        try:
            session = self.get_aiohttp_session()
            current_best_hash = ""

            while not self._exit_event.is_set():
                try:
                    url_to_fetch = f"{self.header_sv_url}/api/v1/chain/tips"
                    request_headers = {'Accept': 'application/json'}
                    async with session.get(url_to_fetch, headers=request_headers) as resp:
                        assert resp.status == 200, resp.reason
                        result = await resp.json()

                    longest_chain_tip = None
                    for tip in result:
                        if tip['state'] == "LONGEST_CHAIN":
                            longest_chain_tip = tip

                    if not longest_chain_tip:  # should never happen
                        raise ValueError("No longest chain tip in response")

                    if current_best_hash != longest_chain_tip['header']['hash']:
                        self.logger.debug("Got new chain tip: %s", longest_chain_tip)
                        current_best_hash = longest_chain_tip['header']['hash']
                        current_best_height = longest_chain_tip['height']
                    else:
                        await asyncio.sleep(1)
                        continue
                except (aiohttp.ClientConnectorError, aiohttp.ServerDisconnectedError) as e:
                    # logger.error("HeaderSV service is unavailable on %s", self.header_sv_url)
                    # Any new websocket connections will be notified when HeaderSV is back online
                    current_best_hash = ""
                    await asyncio.sleep(1)
                    continue
                except Exception:
                    logger.exception("Unexpected exception in header notification task")
                    await asyncio.sleep(1)
                    continue

                if not len(self.get_headers_ws_clients()) and \
                        not len(self.get_account_websockets()):
                    continue

                url_to_fetch = f"{self.header_sv_url}/api/v1/chain/header/{current_best_hash}"
                request_headers = {'Accept': 'application/octet-stream'}
                async with await session.get(url_to_fetch, headers=request_headers) as resp:
                    assert resp.status == 200, resp.reason
                    raw_header = await resp.read()

                tip_notification = raw_header + struct.pack('<I', current_best_height)

                # Send new tip notification to all connected websocket clients
                for ws_id, ws_client in self.get_headers_ws_clients().items():
                    try:
                        self.logger.debug("Sending msg to header websocket client ws_id: %s",
                            ws_client.ws_id)
                        await ws_client.websocket.send_bytes(tip_notification)
                    except ConnectionResetError:
                        self.logger.error("Websocket disconnected")

                # Send new tip notification to all connected websocket clients
                for ws_id, ws_client_general in self.get_account_websockets().items():
                    try:
                        self.logger.debug("Sending msg to general websocket client ws_id: %s",
                            ws_client_general.ws_id)
                        await ws_client_general.websocket.send_json(
                            GeneralNotification(message_type="bsvapi.headers.tip", result=result))
                    except ConnectionResetError:
                        self.logger.error("Websocket disconnected")
        except Exception:
            self.logger.exception("Unexpected exception in header_notifications_thread")
        finally:
            self.logger.info("Closing header push notifications thread")

    # Message Box Websocket Client Get/Add/Remove & Notify thread
    def get_msg_box_ws_clients(self) -> dict[str, MsgBoxWSClient]:
        with self.msg_box_ws_clients_lock:
            return self.msg_box_ws_clients

    def get_ws_clients_by_messagebox_id(self, messagebox_id: int) -> list[MsgBoxWSClient]:
        with self.msg_box_ws_clients_lock:
            return [ self.msg_box_ws_clients[ws_id]
                for ws_id in self.ws_clients_by_messagebox_id.get(messagebox_id, []) ]

    def add_msg_box_ws_client(self, ws_client: MsgBoxWSClient) -> None:
        """Creates a two-way mapping for fast lookups"""
        with self.msg_box_ws_clients_lock:
            self.msg_box_ws_clients[ws_client.ws_id] = ws_client
            if self.ws_clients_by_messagebox_id.get(ws_client.messagebox_id) is None:
                self.ws_clients_by_messagebox_id[ws_client.messagebox_id] = set()
            self.ws_clients_by_messagebox_id[ws_client.messagebox_id].add(ws_client.ws_id)

    def remove_msg_box_ws_client(self, ws_id: str) -> None:
        with self.msg_box_ws_clients_lock:
            msg_box_internal_id = self.msg_box_ws_clients[ws_id].messagebox_id
            del self.msg_box_ws_clients[ws_id]
            self.ws_clients_by_messagebox_id[msg_box_internal_id].remove(ws_id)
            if len(self.ws_clients_by_messagebox_id[msg_box_internal_id]) == 0:
                del self.ws_clients_by_messagebox_id[msg_box_internal_id]

    async def _manage_message_box_notifications_async(self) -> None:
        """Emits any notifications from the queue to all connected websockets"""
        try:
            while not self._exit_event.is_set():
                msgbox_id, notification_data = await self.msgbox_notification_queue.get()
                clients = self.get_ws_clients_by_messagebox_id(msgbox_id)
                self.logger.debug("msgbox[%d] %d notifications", msgbox_id, len(clients))
                for client in clients:
                    try:
                        await client.websocket.send_json(notification_data)
                    except ConnectionResetError:
                        self.logger.error("Websocket[%s] disconnected", client.ws_id)
        except Exception:
            self.logger.exception("Unexpected exception")
        finally:
            self.logger.info("Exiting msgbox notifications task")

    # General Websocket Client Get/Add/Remove & Notify thread
    def get_account_websockets(self) -> dict[str, AccountWebsocketState]:
        with self._account_websocket_state_lock:
            return self._account_websocket_state

    def get_websocket_state_for_account_id(self, account_id: int) -> AccountWebsocketState|None:
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

    async def _manage_account_notifications_async(self) -> None:
        """
        Serialise and send outgoing account-related notifications.
        """
        try:
            while not self._exit_event.is_set():
                account_id, message_kind, payload = await self.account_message_queue.get()
                self.logger.debug("Sending web socket messages to account id=%d", account_id)

                websocket_state = self.get_websocket_state_for_account_id(account_id)
                if websocket_state is None:
                    self.logger.debug("No websocket, dropped message, message_kind=%s, "
                        "account_id=%d", message_kind, account_id)
                    continue

                try:
                    if websocket_state.accept_type == "application/json":
                        # TODO(1.4.0) JSON support. We might consider unpacking this for JSON into
                        #     some dictionary structure rather than just giving them the hex.
                        if isinstance(payload, bytes): # spent output notification
                            payload = payload.hex()
                        await websocket_state.websocket.send_json(GeneralNotification(
                            message_type=ACCOUNT_MESSAGE_NAMES[message_kind], result=payload))
                    else:
                        await websocket_state.websocket.send_bytes(
                            pack_account_message_bytes(message_kind, payload))
                except ConnectionResetError:
                    self.logger.debug("Dropped message for disconnected websocket, "
                        "message_kind=%s, account_id=%d", message_kind, account_id)
        finally:
            self.logger.info("Exiting account push notifications thread")

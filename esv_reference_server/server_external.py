# Copyright(c) 2021-2022 Bitcoin Association.
# Distributed under the Open BSV software license, see the accompanying file LICENSE

import logging
import os
from pathlib import Path
from typing import Optional

from aiohttp import web

from .application_state import ApplicationState
from . import handlers, handlers_headers, handlers_indexer
from . import msg_box
from .msg_box.controller import MsgBoxWebSocket
from .websock import GeneralWebSocket


MODULE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))

logger = logging.getLogger("server")



class ExternalServer:
    def __init__(self, app: web.Application, application_state: ApplicationState, host: str,
            port: int) -> None:
        self.runner: Optional[web.AppRunner] = None
        self._app_state = application_state
        self._app = app
        self._app.on_startup.append(self._on_startup)
        self._app.on_shutdown.append(self._on_shutdown)
        self._app.freeze()  # No further callback modification allowed

        self._host = host
        self._port = port
        self._logger = logging.getLogger("aiohttp-rest-api")

    async def _on_startup(self, app: web.Application) -> None:
        pass

    async def _on_shutdown(self, app: web.Application) -> None:
        self._logger.info("Stopped external server")

    async def start(self) -> None:
        self._logger.info("Started external server on http://%s:%s", self._host, self._port)
        self.runner = web.AppRunner(self._app, access_log=None)
        await self.runner.setup()
        site = web.TCPSite(self.runner, self._host, self._port, reuse_address=True)
        await site.start()
        await self._app_state.wait_for_exit_async(external=True)

    async def stop(self) -> None:
        assert self.runner is not None
        await self.runner.cleanup()

    async def run_async(self) -> None:
        try:
            await self.start()
        finally:
            await self.stop()


def get_external_server_application(app_state: ApplicationState) -> web.Application:
    app = web.Application()

    # This is the standard aiohttp way of managing state within the handlers
    app['app_state'] = app_state
    app['headers_ws_clients'] = app_state.headers_ws_clients
    app['msg_box_ws_clients'] = app_state.msg_box_ws_clients
    app['_account_websocket_state'] = app_state._account_websocket_state

    # Non-optional APIs
    app.add_routes([
        web.get("/", handlers.ping),
        web.get("/api/v1/endpoints", handlers.get_endpoints_data),

        # Payment Channel Account Management
        web.get("/api/v1/account", handlers.get_account),
        web.post("/api/v1/account/key", handlers.post_account_key),
        web.post("/api/v1/account/channel", handlers.post_account_channel),
        web.put("/api/v1/account/channel", handlers.put_account_channel_update),
        web.delete("/api/v1/account/channel", handlers.delete_account_channel),
        web.post("/api/v1/account/funding", handlers.post_account_funding),

        # Message Box Management (i.e. Custom Peer Channels implementation)
        web.get("/api/v1/channel/manage/list", msg_box.controller.list_channels, allow_head=False),
        web.get("/api/v1/channel/manage/{channelid}",
            msg_box.controller.get_single_channel_details),
        web.post("/api/v1/channel/manage/{channelid}",
            msg_box.controller.update_single_channel_properties),
        web.delete("/api/v1/channel/manage/{channelid}", msg_box.controller.delete_channel),
        web.post("/api/v1/channel/manage", msg_box.controller.create_new_channel),
        web.get("/api/v1/channel/manage/{channelid}/api-token/{tokenid}",
            msg_box.controller.get_token_details),
        web.delete("/api/v1/channel/manage/{channelid}/api-token/{tokenid}",
            msg_box.controller.revoke_selected_token),
        web.get("/api/v1/channel/manage/{channelid}/api-token",
            msg_box.controller.get_list_of_tokens),
        web.post("/api/v1/channel/manage/{channelid}/api-token",
            msg_box.controller.create_new_token_for_channel),

        # Message Box Push / Pull API
        web.post("/api/v1/channel/{channelid}", msg_box.controller.write_message),
        # web.head is added automatically by web.get in aiohttp
        web.get("/api/v1/channel/{channelid}", msg_box.controller.get_messages),
        web.post("/api/v1/channel/{channelid}/{sequence}",
            msg_box.controller.mark_message_read_or_unread),
        web.delete("/api/v1/channel/{channelid}/{sequence}", msg_box.controller.delete_message),

        # Message Box Websocket API
        web.view("/api/v1/channel/{channelid}/notify", MsgBoxWebSocket),

        # General-Purpose consolidated Websocket - Requires master bearer token
        web.view("/api/v1/web-socket", GeneralWebSocket),
    ])
    if os.getenv("EXPOSE_HEADER_SV_APIS") == "1":
        app.add_routes([
            web.view("/api/v1/headers/tips/websocket", handlers_headers.HeadersWebSocket),
            web.get("/api/v1/headers/tips", handlers_headers.get_chain_tips),
            web.get("/api/v1/headers/by-height", handlers_headers.get_headers_by_height),
            web.get("/api/v1/headers/{hash}", handlers_headers.get_header),
        ])

    if os.getenv("EXPOSE_PAYMAIL_APIS") == "1":
        pass  # TBD

    if os.getenv("EXPOSE_INDEXER_APIS") == "1":
        app.add_routes([
            web.get("/api/v1/indexer",
                handlers_indexer.indexer_get_indexer_settings),
            web.post("/api/v1/indexer",
                handlers_indexer.indexer_post_indexer_settings),
            # These need to be registered before "get transaction" to avoid clashes.
            web.get("/api/v1/transaction/filter",
                handlers_indexer.indexer_get_transaction_filter),
            web.post("/api/v1/transaction/filter",
                handlers_indexer.indexer_post_transaction_filter),
            web.post("/api/v1/transaction/filter:delete",
                handlers_indexer.indexer_post_transaction_filter_delete),
            # TODO(1.4.0) Technical debt. We can enforce txid with {txid:[a-fA-F0-9]{64}} in theory.
            web.get("/api/v1/transaction/{txid}",
                handlers_indexer.indexer_get_transaction),

            # TODO(1.4.0) Technical debt. We can enforce txid with {txid:[a-fA-F0-9]{64}} in theory.
            web.get("/api/v1/merkle-proof/{txid}",
                handlers_indexer.indexer_get_merkle_proof),
            web.post("/api/v1/restoration/search",
                handlers_indexer.indexer_post_restoration_search),

            web.post("/api/v1/output-spend",
                handlers_indexer.indexer_post_output_spends),
            web.post("/api/v1/output-spend/notifications",
                handlers_indexer.indexer_post_output_spend_notifications),
        ])

    return app

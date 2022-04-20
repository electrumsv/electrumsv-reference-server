# Copyright(c) 2022 Bitcoin Association.
# Distributed under the Open BSV software license, see the accompanying file LICENSE

import logging
import os
from typing import Optional

from aiohttp import web

from .application_state import ApplicationState
from . import handlers, handlers_indexer_internal


class InternalServer:
    def __init__(self, app: web.Application, application_state: ApplicationState, host: str,
            port: int) -> None:
        self._runner: Optional[web.AppRunner] = None
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
        self._logger.info("Stopped internal server")

    async def start(self) -> None:
        self._logger.info("Started internal server on http://%s:%s", self._host, self._port)
        self._runner = web.AppRunner(self._app, access_log=None)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self._host, self._port, reuse_address=True)
        await site.start()
        await self._app_state.wait_for_exit_async(internal=True)

    async def stop(self) -> None:
        assert self._runner is not None
        await self._runner.cleanup()

    async def run_async(self) -> None:
        try:
            await self.start()
        finally:
            await self.stop()



def get_internal_server_application(app_state: ApplicationState) -> web.Application:
    app = web.Application()

    # This is the standard aiohttp way of managing state within the handlers
    app['app_state'] = app_state

    # Non-optional APIs
    app.add_routes([
        web.get("/", handlers.ping),
    ])

    if os.getenv("EXPOSE_INDEXER_APIS") == "1":
        app.add_routes([
            web.post("/api/v1/tip-filter/matches",
                handlers_indexer_internal.indexer_post_tip_filter_matches),
        ])

    return app

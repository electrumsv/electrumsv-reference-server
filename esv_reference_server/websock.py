
# TODO(1.4.0) Rename this file to `websocket_account.py`.

import logging
from typing import cast, TYPE_CHECKING
import uuid

import aiohttp
from aiohttp import web, web_exceptions
from aiohttp.web_ws import WebSocketResponse

from .sqlite_db import SQLiteDatabase
from .types import AccountWebsocketState, AccountWebsocketMediaType
from .utils import _try_read_bearer_token_from_query, _auth_ok

if TYPE_CHECKING:
    from esv_reference_server.server import ApplicationState


class GeneralWebSocket(web.View):
    """
    Each connected client receives account-related notifications on this websocket.

    Protocol versioning is based on the endpoint discovery apiVersion field.
    Requires a master bearer token as this authorizes for notifications from any peer channel
    """

    logger = logging.getLogger("websocket-account")

    async def get(self) -> WebSocketResponse:
        """The communication for this is one-way - for message box notifications only.
        Client messages will be ignored"""
        app_state: 'ApplicationState' = self.request.app['app_state']
        db: SQLiteDatabase = app_state.sqlite_db

        # Note this bearer token is the channel-specific one
        master_api_token = _try_read_bearer_token_from_query(self.request)
        if not master_api_token:
            raise web_exceptions.HTTPBadRequest(
                reason="Missing 'token' query parameter (requires master bearer token)")

        if not _auth_ok(master_api_token, db):
            raise web_exceptions.HTTPUnauthorized(
                reason="Unauthorized - Invalid Token "
                        "(example: ?token=t80Dp_dIk1kqkHK3P9R5cpDf67JfmNixNscexEYG0"
                        "_xaCbYXKGNm4V_2HKr68ES5bytZ8F19IS0XbJlq41accQ==)")

        # TODO(1.4.0) Accounts. Until we have free quota accounts we need a way to
        #     access the server as if we were doing so with an account. This should be removed
        #     when we have proper account usage in ESV.
        assert app_state.temporary_account_id is not None
        account_id = app_state.temporary_account_id

        ws_id = str(uuid.uuid4())
        accept_type_text = self.request.headers.get('Accept', 'application/json')
        if accept_type_text == "*/*":
            accept_type_text = 'application/json'
        accept_type = cast(AccountWebsocketMediaType, accept_type_text)
        websocket_response = web.WebSocketResponse()
        await websocket_response.prepare(self.request)
        websocket_state = AccountWebsocketState(
            ws_id=ws_id,
            websocket=websocket_response,
            account_id=account_id,
            accept_type=accept_type
        )
        # TODO(1.4.0) If there is an existing connection for this account close it.
        app_state.setup_account_websocket(websocket_state)
        self.logger.debug(
            'Account websocket connected, host=%s, accept_type=%s, websocket_id=%s, account_id=%d',
            self.request.host, accept_type, websocket_state.ws_id, account_id)
        try:
            await self._websocket_message_loop(websocket_state)
        finally:
            if not websocket_response.closed:
                await websocket_response.close()
            self.logger.debug("Account websocket disconnected, websocket_id=%s", ws_id)
            app_state.teardown_account_websocket(ws_id)

        return websocket_response

    async def _websocket_message_loop(self, websocket_state: AccountWebsocketState) -> None:
        # Loop until the connection is closed. This is a broken usage of the `for` loop by
        # aiohttp, where the number of iterations is not bounded.
        async for message in websocket_state.websocket:
            if message.type in (aiohttp.WSMsgType.text, aiohttp.WSMsgType.binary):
                # We do not accept incoming messages. To ignore them would be to encourage badly
                # implemented clients.
                await websocket_state.websocket.close()

            elif message.type == aiohttp.WSMsgType.error:
                self.logger.error('Account websocket connection closed with exception',
                    exc_info=websocket_state.websocket.exception())

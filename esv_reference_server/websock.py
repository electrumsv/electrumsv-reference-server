import logging
import uuid

import aiohttp
from typing import Union
import typing
from aiohttp import web
from aiohttp.web_ws import WebSocketResponse

from esv_reference_server import errors
from esv_reference_server.errors import Error
from esv_reference_server.msg_box.controller import _auth_ok
from esv_reference_server.sqlite_db import SQLiteDatabase
from esv_reference_server.types import GeneralWSClient
from esv_reference_server.utils import _try_read_bearer_token_from_query

if typing.TYPE_CHECKING:
    from esv_reference_server.server import ApplicationState


class GeneralWebSocket(web.View):
    """This is the general-purpose consolidated websocket. Protocol versioning is based
    on the endpoint discovery apiVersion field. If the headers APIs are not listed then
    there will be no tip notifications. The same applies to any future optional extension
    APIs.

    Requires a master bearer token as this authorizes for notifications from any peer channel
    """

    logger = logging.getLogger("general-websocket")

    async def get(self) -> Union[WebSocketResponse, web.Response]:
        """The communication for this is one-way - for message box notifications only.
        Client messages will be ignored"""
        app_state: 'ApplicationState' = self.request.app['app_state']
        db: SQLiteDatabase = app_state.sqlite_db
        accept_type = self.request.headers.get('Accept', 'application/json')
        ws = None
        ws_id = str(uuid.uuid4())

        try:
            # Note this bearer token is the channel-specific one
            master_api_token = _try_read_bearer_token_from_query(self.request)
            if not master_api_token:
                raise Error(reason="Missing 'token' query parameter (requires master bearer token)",
                            status=400)
            if not _auth_ok(master_api_token, db):
                raise Error(reason="Unauthorized - Invalid Token (example: ?token=t80Dp_dIk1kqkHK3P9R5cpDf67JfmNixNscexEYG0_xaCbYXKGNm4V_2HKr68ES5bytZ8F19IS0XbJlq41accQ==)",
                            status=401)

            ws = web.WebSocketResponse()
            await ws.prepare(self.request)
            client = GeneralWSClient(
                ws_id=ws_id,
                websocket=ws,
                accept_type=accept_type
            )
            app_state.add_ws_client(client)
            self.logger.debug('%s connected. host=%s. accept_type=%s',
                              client.ws_id, self.request.host, accept_type)
            await self._handle_new_connection(client)
            return ws
        except Error as e:
            return web.Response(reason=e.reason, status=e.status)
        finally:
            if ws and not ws.closed:
                await ws.close()
                self.logger.debug("removing general websocket id: %s", ws_id)
                if self.request.app['general_ws_clients'].get(ws_id):
                    del self.request.app['general_ws_clients'][ws_id]

    async def _handle_new_connection(self, client: GeneralWSClient) -> None:
        async for msg in client.websocket:
            # Ignore all messages from client
            if msg.type == aiohttp.WSMsgType.text:
                pass

            elif msg.type == aiohttp.WSMsgType.error:
                # 'client.websocket.exception()' merely returns ClientWebSocketResponse._exception
                # without a traceback. see aiohttp.ws_client.py:receive for details.
                self.logger.error('ws connection closed with exception %s',
                                  client.websocket.exception())

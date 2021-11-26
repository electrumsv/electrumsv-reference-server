import json

import aiohttp
import typing
from aiohttp import web, WSCloseCode
import logging
import uuid

from esv_reference_server import errors
from esv_reference_server.errors import Error
from esv_reference_server.msg_box.controller import _auth_for_channel_token, _try_read_bearer_token
from esv_reference_server.msg_box.repositories import MsgBoxSQLiteRepository
from esv_reference_server.types import MsgBoxWSClient

if typing.TYPE_CHECKING:
    from esv_reference_server.server import ApplicationState


class MsgBoxWebSocket(web.View):
    logger = logging.getLogger("message-box-websocket")

    async def get(self):
        """The communication for this is one-way - for message box notifications only.
        Client messages will be ignored"""
        app_state: 'ApplicationState' = self.request.app['app_state']
        msg_box_repository: MsgBoxSQLiteRepository = app_state.msg_box_repository
        accept_type = self.request.headers.get('Accept')
        ws = web.WebSocketResponse()
        await ws.prepare(self.request)
        ws_id = str(uuid.uuid4())

        try:
            account_id = 0
            external_id = self.request.match_info.get('channelid')
            if not external_id:
                raise Error(reason="channel id wasn't provided", status=404)

            # Note this bearer token is the channel-specific one
            msg_box_api_token = _try_read_bearer_token(self.request)
            if not msg_box_api_token:
                raise Error(reason=errors.NoBearerToken.reason, status=errors.NoBearerToken.status)

            if not _auth_for_channel_token(msg_box_api_token, external_id, msg_box_repository):
                raise Error(reason="unauthorized", status=web.HTTPUnauthorized.status_code)

            msg_box_external_id = self.request.match_info.get('channelid')
            msg_box = msg_box_repository.get_msg_box(account_id, external_id)
            client = MsgBoxWSClient(
                ws_id=ws_id, websocket=ws,
                msg_box_internal_id=msg_box.id,
                accept_type=accept_type
            )
            app_state.add_msg_box_ws_client(client)
            self.logger.debug('%s connected. host=%s. channel_id=%s, accept_type=%s',
                client.ws_id, self.request.host, msg_box_external_id, accept_type)
            await self._handle_new_connection(client)
            return ws
        except Error as e:
            await ws.send_json(e.to_websocket_dict())
            await ws.close()
        finally:
            if not ws.closed:
                await ws.close()
                self.logger.debug("removing msg box websocket id: %s", ws_id)
                del self.request.app['msg_box_ws_clients'][ws_id]

    async def _handle_new_connection(self, client: MsgBoxWSClient):
        # self.msg_box_ws_clients = self.request.app['msg_box_ws_clients']

        async for msg in client.websocket:
            # Ignore all messages from client
            if msg.type == aiohttp.WSMsgType.text:
                self.logger.debug('%s new message box websocket client sent (message ignored): %s',
                    client.ws_id, msg.data)

            elif msg.type == aiohttp.WSMsgType.error:
                # 'client.websocket.exception()' merely returns ClientWebSocketResponse._exception
                # without a traceback. see aiohttp.ws_client.py:receive for details.
                self.logger.error('ws connection closed with exception %s',
                    client.websocket.exception())

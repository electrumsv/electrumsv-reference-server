import aiohttp
from aiohttp import web
import logging
import uuid

from esv_reference_server.types import MsgBoxWSClient


class MsgBoxWebSocket(web.View):
    logger = logging.getLogger("message-box-websocket")

    async def get(self):
        """The communication for this is one-way - for message box notifications only.
        Client messages will be ignored"""
        app_state = self.request.app['app_state']
        ws = web.WebSocketResponse()
        await ws.prepare(self.request)
        ws_id = str(uuid.uuid4())

        accept_type = self.request.headers.get('Accept')
        channelid = self.request.match_info.get('channelid')

        try:
            client = MsgBoxWSClient(ws_id=ws_id, websocket=ws, channel_id=channelid, accept_type=accept_type)
            app_state.add_ws_client(client)
            self.logger.debug('%s connected. host=%s. channel_id=%s, accept_type=%s', client.ws_id, self.request.host, channelid, accept_type)
            await self._handle_new_connection(client)
            return ws
        finally:
            await ws.close()
            self.logger.debug("removing msg box websocket id: %s", ws_id)
            del self.request.app['msg_box_ws_clients'][ws_id]

    async def _handle_new_connection(self, client: MsgBoxWSClient):
        self.msg_box_ws_clients = self.request.app['msg_box_ws_clients']

        async for msg in client.websocket:
            # Ignore all messages from client
            if msg.type == aiohttp.WSMsgType.text:
                self.logger.debug('%s new message box websocket client sent: %s', client.ws_id, msg.data)
                # request_json = json.loads(msg.data)
                # response_json = json.dumps(request_json)
                # await client.websocket.send_str(response_json)

            elif msg.type == aiohttp.WSMsgType.error:
                # 'client.websocket.exception()' merely returns ClientWebSocketResponse._exception
                # without a traceback. see aiohttp.ws_client.py:receive for details.
                self.logger.error('ws connection closed with exception %s',
                    client.websocket.exception())

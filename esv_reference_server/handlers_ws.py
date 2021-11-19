import os

import aiohttp
import bitcoinx
from aiohttp import web
import logging
import uuid


class WSClient(object):

    def __init__(self, ws_id: str, websocket: web.WebSocketResponse):
        self.ws_id = ws_id
        self.websocket = websocket


class HeadersWebSocket(web.View):
    logger = logging.getLogger("headers-websocket")

    async def get(self):
        """The communication for this is one-way - for header notifications only.
        Client messages will be ignored"""
        ws = web.WebSocketResponse()
        await ws.prepare(self.request)
        ws_id = str(uuid.uuid4())

        try:
            client = WSClient(ws_id=ws_id, websocket=ws)
            self.request.app['app_state'].add_ws_client(client)
            self.logger.debug('%s connected. host=%s.', client.ws_id, self.request.host)
            await self._handle_new_connection(client)
            return ws
        finally:
            await ws.close()
            self.logger.debug("removing websocket id: %s", ws_id)
            del self.request.app['ws_clients'][ws_id]

    async def _send_chain_tip(self, client: WSClient):
        """Called once on initial connection"""
        client_session: aiohttp.ClientSession = self.request.app['client_session']
        app_state = self.request.app['app_state']
        try:
            request_headers = {'Accept': 'application/json'}
            url_to_fetch = f"{app_state.header_sv_url}/api/v1/chain/tips"
            async with client_session.get(url_to_fetch, headers=request_headers) as response:
                result = await response.json()
                for tip in result:
                    if tip['state'] == "LONGEST_CHAIN":
                        longest_chain_tip = tip
                        current_best_hash = longest_chain_tip['header']['hash']
                        current_best_height = longest_chain_tip['height']

            # Todo: this should actually be 'Accept' but HeaderSV uses 'Content-Type'
            request_headers = {'Content-Type': 'application/octet-stream'}
            url_to_fetch = f"{app_state.header_sv_url}/api/v1/chain/header/{current_best_hash}"
            async with client_session.get(url_to_fetch, headers=request_headers) as response:
                result = await response.read()
                self.logger.debug(f"Sending tip to new websocket connection, ws_id: {client.ws_id}")
                response = bytearray()
                response += result  # 80 byte header
                response += bitcoinx.pack_be_uint32(current_best_height)
                await client.websocket.send_bytes(response)
        except aiohttp.ClientConnectorError as e:
            # When HeaderSV comes back online there will be a compensating chain tip notification
            self.logger.error(f"HeaderSV service is unavailable on {app_state.header_sv_url}")
            pass

    async def _handle_new_connection(self, client: WSClient):
        self.ws_clients = self.request.app['ws_clients']
        await self._send_chain_tip(client)

        async for msg in client.websocket:
            # Ignore all messages from client
            if msg.type == aiohttp.WSMsgType.text:
                self.logger.debug('%s client sent: %s', client.ws_id, msg.data)
                # request_json = json.loads(msg.data)
                # response_json = json.dumps(request_json)
                # await client.websocket.send_str(response_json)

            elif msg.type == aiohttp.WSMsgType.error:
                # 'client.websocket.exception()' merely returns ClientWebSocketResponse._exception
                # without a traceback. see aiohttp.ws_client.py:receive for details.
                self.logger.error('ws connection closed with exception %s',
                    client.websocket.exception())

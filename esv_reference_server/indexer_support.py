# Copyright(c) 2021-2022 Bitcoin Association.
# Distributed under the Open BSV software license, see the accompanying file LICENSE

# In order to develop, run and maintain an indexer, requires a business. It is expected that
# businesses can adapt this reference server to provide a public facing interface to their indexing
# services (or provide compatible APIs in their own implementation).
#
# The simple indexer that the ElectrumSV project provides is only intended for use against the
# regtest network, and no other network. It's primary goal is to aid in the development of
# ElectrumSV.
#

from __future__ import annotations
import asyncio, logging
from typing import cast, TYPE_CHECKING

import aiohttp
from aiohttp.web import WSMsgType

from .constants import AccountMessageKind
from .types import AccountMessage, Outpoint, outpoint_struct, output_spend_struct, OutputSpend

if TYPE_CHECKING:
    from .application_state import ApplicationState


logger = logging.getLogger("support-indexer")



async def unregister_unwanted_spent_outputs(app_state: ApplicationState, account_id: int,
        outpoints_to_unregister: set[Outpoint]) -> None:
    """
    Clean up any indexer state associated with this account.

    It is assumed that any failure to communicate with the indexer is because the indexer went
    down and any subscriptions will be remade when we are able to open the websocket we maintain
    with them.
    """
    logger.debug("unregistering unwanted spent output registrations for account_id=%d", account_id)

    byte_buffer = bytearray(len(outpoints_to_unregister) * outpoint_struct.size)
    for output_index, outpoint in enumerate(outpoints_to_unregister):
        outpoint_struct.pack_into(byte_buffer, output_index * outpoint_struct.size, *outpoint)

    # TODO(1.4.0) Indexer. Consider any race conditions where a user establishes a new
    #     connection and the old indexer registrations are removed after the new ones are
    #     put in place.
    indexer_url = f"{app_state.indexer_url}/api/v1/output-spend/notifications:unregister"
    client_session = app_state.get_aiohttp_session()
    try:
        async with client_session.post(indexer_url, body=byte_buffer) as response:
            if not response.ok:
                # This may be intentional if the indexer has been taken down. If the web socket
                # to the indexer goes down, then we reregister on reconnection.
                logger.warning("on_account_disconnected failed to notify indexer of "
                    "unregistered outpoints, status=%d, reason=%s", response.status,
                    response.reason)
    except aiohttp.ClientError as exc:
        logger.warning("on_account_disconnected failed to notify indexer of "
            "unregistered outpoints", exc_info=exc)


# This task is created and killed by the application state object.
async def maintain_indexer_connection_async(application_state: ApplicationState) -> None:
    """
    This is intended to be self-encapsulated management of the websocket connection to the
    indexing server. It should recover from errors so that if it can have a connection to the
    indexing server, it should have one.
    """
    client_session = application_state.get_aiohttp_session()
    assert application_state.indexer_url is not None
    websocket_url = f"{application_state.indexer_url}/ws"

    logger.debug("Entering maintain_indexer_connection")
    try:
        message_to_ignore: str | None = None
        while not application_state._exit_event.is_set():
            show_retry_message = True
            show_ongoing_retries_message = False
            try:
                await manage_indexer_websocket(application_state, client_session, websocket_url)
            except aiohttp.ServerConnectionError:
                # Exit as we want to retry.
                logger.error("Indexer websocket server connection timeout")
                message_to_ignore = None # Allow repeated messages.
            except aiohttp.ClientConnectorError:
                # Exit as we want to retry.
                show_retry_message = False
                current_message = "Indexer websocket server connection could not be established"
                if message_to_ignore != current_message:
                    logger.error(current_message)
                    message_to_ignore = current_message # Skip repeated messages.
                    show_ongoing_retries_message = True
            except aiohttp.ClientError:
                # We retry these and log them as they are in theory unexpected and the user might
                # shut down the indexer and restart it after fixing it.
                logger.exception("Unexpected exception in indexer web socket management")
                message_to_ignore = None # Allow repeated messages.
            else:
                message_to_ignore = None # Allow repeated messages.
            finally:
                application_state.indexer_is_connected = False

            if show_ongoing_retries_message:
                logger.debug("Not connected to indexer; retrying every 10 seconds")
            elif show_retry_message:
                logger.debug("Not connected to indexer; retrying in 10 seconds")
            await asyncio.sleep(10)
    finally:
        logger.debug("Exiting maintain_indexer_connection")


async def manage_indexer_websocket(application_state: ApplicationState,
        client_session: aiohttp.ClientSession, websocket_url: str) -> None:
    async with client_session.ws_connect(websocket_url) as websocket:
        logger.debug("Connected to indexer websocket")
        application_state.indexer_is_connected = True
        async for message in websocket:
            if message.type == WSMsgType.ERROR:
                logger.error("Unhandled websocket message type %s", message.type,
                    exc_info=message.data)
                break
            elif message.type == WSMsgType.BINARY:
                message_bytes = cast(bytes, message.data)
                # NOTE At this time spent outputs are the only data format so there is no
                #     envelope format used to differentiate packet sizes yet.
                spent_output = OutputSpend(*output_spend_struct.unpack(message_bytes))
                logger.debug("Spent output notification from indexer of %r", spent_output)
                outpoint = Outpoint(spent_output.out_tx_hash, spent_output.out_index)
                logger.debug("Spent output notification outpoint=%r", outpoint)
                for websocket_state in application_state.get_account_websockets().values():
                    logger.debug("Websocket account_id=%d, registrations=%r",
                        websocket_state.account_id, websocket_state.spent_output_registrations)
                    if outpoint in websocket_state.spent_output_registrations:
                        logger.debug("Broadcasting spent output notification to account %d",
                            websocket_state.account_id)
                        application_state.account_message_queue.put_nowait(AccountMessage(
                            websocket_state.account_id, AccountMessageKind.SPENT_OUTPUT_EVENT,
                            message_bytes))
            else:
                logger.error("Unhandled websocket message type %s", message.type)
                break
        logger.debug("Websocket loop exit")

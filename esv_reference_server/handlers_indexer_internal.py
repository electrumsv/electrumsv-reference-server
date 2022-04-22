# Copyright(c) 2022 Bitcoin Association.
# Distributed under the Open BSV software license, see the accompanying file LICENSE
#
# The goal of this file is to allow non-public applications to have access to a secure API.

from http import HTTPStatus
import logging
from typing import Optional

import aiohttp
from aiohttp import web
from bitcoinx import hex_str_to_hash

from .application_state import ApplicationState
from . import sqlite_db
from .types import TipFilterNotificationBatch, TipFilterNotificationMatch


logger = logging.getLogger("handlers-indexer-internal")


FilterMatch = tuple[bytes, bytes, int, int]


async def indexer_post_tip_filter_matches(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app["app_state"]

    content_type = request.headers.get("Content-Type", "application/json")
    if content_type != "application/json":
        raise web.HTTPBadRequest(reason="Invalid 'Content-Type', "
            f"expected 'application/json', got '{content_type}'")

    batch: TipFilterNotificationBatch = await request.json()
    session = app_state.get_aiohttp_session()

    block_hash: Optional[bytes] = None
    if batch["blockId"] is not None:
        block_hash = hex_str_to_hash(batch["blockId"])
    account_ids = [ entry["accountId"] for entry in batch["entries"] ]

    rows = sqlite_db.read_account_indexer_metadata(app_state.database_context, account_ids)
    metadata_by_account_id = { row.account_id: row for row in rows }
    entry_failures = list[tuple[int, Optional[bytes], list[TipFilterNotificationMatch], str]]()
    for entry in batch["entries"]:
        account_id = entry["accountId"]
        metadata = metadata_by_account_id.get(account_id, None)
        if metadata is None:
            logger.error("Skipping tip filter match for missing account %d", account_id)
            continue

        if metadata.tip_filter_callback_url is None:
            logger.error("Skipping tip filter match for account %d with no callback URL",
                account_id)
            continue

        url = metadata.tip_filter_callback_url
        headers = {
            "Content-Type":     "application/octet-stream",
            "Authorization":    f"Bearer {metadata.tip_filter_callback_token}",
        }
        json_object = [ block_hash, entry["matches"] ]
        try:
            async with session.post(url, headers=headers, json=json_object) as response:
                if response.status == HTTPStatus.OK:
                    logger.debug("Posted message to peer channel status=%s, reason=%s",
                        response.status, response.reason)
                    continue

                logger.error("Failed to post peer channel response status=%s, reason=%s",
                    response.status, response.reason)
                entry_failures.append((account_id, block_hash, entry["matches"], ""))
        except aiohttp.ClientError:
            logger.exception("Failed to post peer channel response")
            entry_failures.append((account_id, block_hash, entry["matches"], ""))

    # TODO(1.4.0) Unfinished code. entry failures.

    return web.Response()


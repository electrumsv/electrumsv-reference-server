# Copyright(c) 2022 Bitcoin Association.
# Distributed under the Open BSV software license, see the accompanying file LICENSE
#
# The goal of this file is to allow non-public applications to have access to a secure API.

import dataclasses
import hashlib
from http import HTTPStatus
import json
import logging
import time
from typing import Optional

import aiohttp
from aiohttp import web

from .application_state import ApplicationState
from .constants import OutboundDataFlag
from . import sqlite_db
from .types import OutboundDataLogRow, OutboundDataRow, TipFilterPushDataMatchesData, \
    TipFilterNotificationBatch


logger = logging.getLogger("handlers-indexer-internal")



@dataclasses.dataclass
class EntryResult:
    account_id: int
    outbound_data_id: Optional[int]
    outbound_data_flags: OutboundDataFlag

    json_text: Optional[str]
    content_type: Optional[str]
    response_status_code: Optional[int]
    response_reason: Optional[str]


async def indexer_post_tip_filter_matches(request: web.Request) -> web.Response:
    app_state: ApplicationState = request.app["app_state"]

    content_type = request.headers.get("Content-Type", "application/json")
    if content_type != "application/json":
        raise web.HTTPBadRequest(reason="Invalid 'Content-Type', "
            f"expected 'application/json', got '{content_type}'")

    batch: TipFilterNotificationBatch = await request.json()
    session = app_state.get_aiohttp_session()

    account_ids = [ entry["accountId"] for entry in batch["entries"] ]

    rows = sqlite_db.read_account_indexer_metadata(app_state.database_context, account_ids)
    metadata_by_account_id = { row.account_id: row for row in rows }
    entry_results = list[EntryResult]()
    for entry in batch["entries"]:
        flags = OutboundDataFlag.TIP_FILTER_NOTIFICATIONS
        account_id = entry["accountId"]
        metadata = metadata_by_account_id.get(account_id, None)
        if metadata is None:
            logger.error("Skipping tip filter match for missing account %d", account_id)
            continue

        url = metadata.tip_filter_callback_url

        json_object: TipFilterPushDataMatchesData = {
            "blockId": batch["blockId"],
            "matches": entry["matches"],
        }
        json_text = json.dumps(json_object)

        if url is None:
            logger.error("Skipping tip filter match for account %d with no callback URL",
                account_id)
            flags |= OutboundDataFlag.DISPATCH_NO_CALLBACK
            entry_results.append(EntryResult(account_id, None, flags, json_text, content_type,
                None, None))
            continue

        headers = {
            "Content-Type":     content_type,
        }
        if metadata.tip_filter_callback_token is not None:
            headers["Authorization"] = metadata.tip_filter_callback_token
        try:
            async with session.post(url, headers=headers, data=json_text) as response:
                if response.status == HTTPStatus.OK:
                    logger.debug("Posted message to peer channel status=%s, reason=%s",
                        response.status, response.reason)
                else:
                    logger.error("Failed to post peer channel response status=%s, reason=%s",
                        response.status, response.reason)
                entry_results.append(EntryResult(account_id, None, flags, json_text, content_type,
                    response.status, response.reason))
        except aiohttp.ClientError:
            logger.exception("Failed to post peer channel response")
            flags |= OutboundDataFlag.DISPATCH_EXCEPTION
            entry_results.append(EntryResult(account_id, None, flags, json_text, content_type,
                None, None))

    date_created = int(time.time())
    failure_data_creation_rows = list[OutboundDataRow]()
    success_log_creation_rows = list[OutboundDataLogRow]()
    log_creation_rows_by_key = dict[tuple[int, bytes], OutboundDataLogRow]()
    for result in entry_results:
        log_row = OutboundDataLogRow(result.account_id, None, result.outbound_data_flags,
            result.response_status_code, result.response_reason, date_created)

        if result.response_status_code == HTTPStatus.OK:
            success_log_creation_rows.append(log_row)
        else:
            assert result.json_text is not None
            outbound_data_bytes = result.json_text.encode()
            # We use the hash to match allocated id to what row it was allocated for.
            hasher = hashlib.blake2b(digest_size=20)
            hasher.update(outbound_data_bytes)
            outbound_data_hash = hasher.digest()
            data_creation_row = OutboundDataRow(None, result.account_id, outbound_data_bytes,
                outbound_data_hash, OutboundDataFlag.TIP_FILTER_NOTIFICATIONS,
                content_type, date_created)
            failure_data_creation_rows.append(data_creation_row)
            log_creation_rows_by_key[(result.account_id, outbound_data_hash)] = log_row

    if len(failure_data_creation_rows) > 0:
        logger.debug("Recording %d peer channel broadcast failures",
            len(failure_data_creation_rows))
        app_state.database_context.run_in_thread(sqlite_db.create_outbound_datas_write,
            failure_data_creation_rows, log_creation_rows_by_key)

    if len(success_log_creation_rows):
        app_state.database_context.run_in_thread(
            sqlite_db.create_outbound_data_logs_write, success_log_creation_rows)

    return web.Response()


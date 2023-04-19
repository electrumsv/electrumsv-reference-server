import asyncio
import hashlib
from http import HTTPStatus
import os
import random
from typing import Any
import unittest.mock

import aiohttp
from bitcoinx import PrivateKey, PublicKey
import pytest

from esv_reference_server.constants import IndexerPushdataRegistrationFlag, OutboundDataFlag
from esv_reference_server.application_state import ApplicationState
from esv_reference_server import sqlite_db
from esv_reference_server.sqlite_db import create_account, \
    create_indexer_filtering_registrations_pushdatas, \
    DatabaseStateModifiedError, delete_indexer_filtering_registrations_pushdatas, \
    read_indexer_filtering_registrations_pushdatas, prune_indexer_filtering, \
    update_indexer_filtering_registrations_pushdatas_flags
from esv_reference_server.types import OutboundDataLogRow, OutboundDataRow, TipFilterListEntry, \
    TipFilterRegistrationEntry


PRIVATE_KEY_1 = PrivateKey.from_hex(
    "720f1987db69efa562b3dabd78e51f19bd8da76c70ad839b72b939f4071b144b")
PUBLIC_KEY_1: PublicKey = PRIVATE_KEY_1.public_key


# We store this so that we can mock it.
asyncio_sleep = asyncio.sleep


@unittest.mock.patch('esv_reference_server.sqlite_db.time.time')
def test_filtering_pushdata_hash_registration(time: unittest.mock.Mock) -> None:
    assert ApplicationState.singleton_reference is not None
    application_state = ApplicationState.singleton_reference()
    assert application_state is not None

    account_id, api_key = application_state.database_context.run_in_thread(
        create_account, PUBLIC_KEY_1.to_bytes(compressed=True))

    time.side_effect = lambda *args: 1.0

    duration_seconds = 2

    # Create the first pushdata as a non-finalised registration.
    pushdata_hash_1 = os.urandom(32)
    pushdata_hashes = [ pushdata_hash_1 ]
    creation_rows_1 = [ TipFilterRegistrationEntry(pushdata_hash_1, duration_seconds) ]

    date_created = application_state.database_context.run_in_thread(
        create_indexer_filtering_registrations_pushdatas, account_id, creation_rows_1)
    assert date_created is not None

    # That that update of pushdata flags errors if all provided pushdata are required to be updated
    # and not all are matched due to custom filtering.
    with pytest.raises(DatabaseStateModifiedError):
        application_state.database_context.run_in_thread(
            update_indexer_filtering_registrations_pushdatas_flags,
                account_id, pushdata_hashes,
                update_flags=IndexerPushdataRegistrationFlag.FINALISED,
                filter_flags=IndexerPushdataRegistrationFlag.FINALISED,
                require_all=True)

    # Finalise the first pushdata as fully registered on the indexer.
    application_state.database_context.run_in_thread(
        update_indexer_filtering_registrations_pushdatas_flags,
        account_id, pushdata_hashes, update_flags=IndexerPushdataRegistrationFlag.FINALISED)

    time.side_effect = lambda *args: 2.0

    # Creating anything in addition to something being registered at this point conflicts and fails.
    pushdata_hash_2 = os.urandom(32)
    creation_rows_2 = creation_rows_1 + \
        [ TipFilterRegistrationEntry(pushdata_hash_2, duration_seconds) ]

    assert application_state.database_context.run_in_thread(
        create_indexer_filtering_registrations_pushdatas, account_id,
        creation_rows_2) is None

    application_state.database_context.run_in_thread(prune_indexer_filtering,
        IndexerPushdataRegistrationFlag.FINALISED, IndexerPushdataRegistrationFlag.FINALISED)

    list_1 = read_indexer_filtering_registrations_pushdatas(application_state.database_context,
        account_id)
    assert list_1 == []

    # Recreate both pushdatas as non-finalised.
    date_created_2 = application_state.database_context.run_in_thread(
        create_indexer_filtering_registrations_pushdatas, account_id,
        creation_rows_2)
    assert date_created_2 is not None

    list_rows_2_set = {
        TipFilterListEntry(entry.pushdata_hash, date_created_2, entry.duration_seconds)
        for entry in creation_rows_2 }

    list_2 = read_indexer_filtering_registrations_pushdatas(application_state.database_context,
        account_id)
    assert set(list_2) == list_rows_2_set

    # Only finalised pushdatas are read, and there are none.
    list_3 = read_indexer_filtering_registrations_pushdatas(application_state.database_context,
        account_id,
        IndexerPushdataRegistrationFlag.FINALISED, IndexerPushdataRegistrationFlag.FINALISED)
    assert list_3 == []

    application_state.database_context.run_in_thread(
        update_indexer_filtering_registrations_pushdatas_flags,
        account_id, [ pushdata_hash_1, pushdata_hash_2 ],
        update_flags=IndexerPushdataRegistrationFlag.FINALISED)

    # Now that the pushdatas are finalised ensure they are read.
    list_4 = read_indexer_filtering_registrations_pushdatas(application_state.database_context,
        account_id,
        IndexerPushdataRegistrationFlag.FINALISED, IndexerPushdataRegistrationFlag.FINALISED)
    assert set(list_4) == list_rows_2_set

    # Delete one pushdata leaving the other in place.
    application_state.database_context.run_in_thread(
        delete_indexer_filtering_registrations_pushdatas, account_id, [ pushdata_hash_1 ])

    # Check that the first was deleted and the second remains.
    list_5 = read_indexer_filtering_registrations_pushdatas(application_state.database_context,
        account_id,
        IndexerPushdataRegistrationFlag.FINALISED, IndexerPushdataRegistrationFlag.FINALISED)
    assert list_5 ==  [ TipFilterListEntry(creation_rows_2[1].pushdata_hash, date_created_2,
        creation_rows_2[1].duration_seconds) ]

    # Check that pruning by expiry date works.
    date_expires = date_created_2 + duration_seconds
    assert 1 == application_state.database_context.run_in_thread(prune_indexer_filtering,
        IndexerPushdataRegistrationFlag.NONE, IndexerPushdataRegistrationFlag.NONE,
        date_expires)


@pytest.mark.asyncio
@unittest.mock.patch('time.time')
@unittest.mock.patch('esv_reference_server.application_state.asyncio.sleep')
@unittest.mock.patch('aiohttp.ClientSession._request')
async def test_outbound_data_and_logs(request_mock: unittest.mock.Mock,
        sleep_mock: unittest.mock.Mock, time_mock: unittest.mock.Mock) -> None:
    """
    This test is a little heavy and covers the following:
    - Database calls related to outbound data and outbound data logs.
    - The outbound data delivery task in the application state.
    """
    # TODO(technical-debt) Altering the time using the monkey-patched mock affects everything
    #     that uses the time, including the logging. It would probably be better to have some
    #     `get_time` method on the application state, and to mock that.
    assert ApplicationState.singleton_reference is not None
    application_state = ApplicationState.singleton_reference()
    assert application_state is not None

    account_ids = list[int]()
    for i in range(10):
        account_id, api_key = await application_state.database_context.run_in_thread_async(
            create_account, PUBLIC_KEY_1.to_bytes(compressed=True))
        account_ids.append(account_id)

    current_time = 1.0
    time_mock.side_effect = lambda *args: current_time

    data_creation_rows = list[OutboundDataRow]()
    log_creation_rows_by_key = dict[tuple[int, bytes], OutboundDataLogRow]()

    for row_index in range(30):
        outbound_data_bytes = "".join(chr(random.randrange(32, 90)) for i in range(2048)).encode()

        hasher = hashlib.blake2b(digest_size=20)
        hasher.update(outbound_data_bytes)
        outbound_data_hash = hasher.digest()

        account_id = account_ids[row_index % len(account_ids)]
        content_type = random.choice([ "application/json", "application/octet-stream" ])
        current_time += 1.0
        data_creation_row = OutboundDataRow(None, account_id, outbound_data_bytes,
            outbound_data_hash, OutboundDataFlag.TIP_FILTER_NOTIFICATIONS,
            content_type, int(current_time))
        data_creation_rows.append(data_creation_row)

        log_creation_rows_by_key[(account_id, outbound_data_hash)] = \
            OutboundDataLogRow(account_id, None, data_creation_row.outbound_data_flags,
                HTTPStatus.BAD_REQUEST, "Fake reason", int(current_time))

    await application_state.database_context.run_in_thread_async(
        sqlite_db.create_outbound_datas_write, data_creation_rows, log_creation_rows_by_key)

    # Find all the rows that have zeroed flags, there are none, we always set flags above.
    pending_rows_1 = sqlite_db.read_pending_outbound_datas(application_state.database_context,
        OutboundDataFlag.NONE, ~OutboundDataFlag.NONE)
    assert len(pending_rows_1) == 0

    # Find all the rows that are the ones we should have added (by flag masking).
    pending_rows_2 = sqlite_db.read_pending_outbound_datas(application_state.database_context,
        OutboundDataFlag.TIP_FILTER_NOTIFICATIONS, OutboundDataFlag.TIP_FILTER_NOTIFICATIONS)
    assert len(pending_rows_2) == len(data_creation_rows)

    # Check that the created log rows get the correct outbound data table foreign key value.
    # These are assigned by matching the hash (which is necessary because SQLite does not return
    # ids in the order the insertion rows were passed in).
    pending_ids_2 = set(row.outbound_data_id for row in pending_rows_2
        if row.outbound_data_id is not None)
    assert len(pending_ids_2) == len(data_creation_rows)

    update_rows = list[tuple[OutboundDataFlag, int]]()
    non_updated_ids = pending_ids_2.copy()
    for i in range(5):
        update_id = pending_rows_2[i].outbound_data_id
        # We update it with this invalid flag (it does not have the tip filter flag) and
        # this if encountered is an indicator that these are not the rows we want.
        update_rows.append((OutboundDataFlag.DISPATCHED_SUCCESSFULLY, update_id))
        non_updated_ids.remove(update_id)

    await application_state.database_context.run_in_thread_async(
        sqlite_db.update_outbound_data_flags_write, update_rows)

    # Find all the rows remaining that we did not mark as dispatched.
    pending_rows_3 = sqlite_db.read_pending_outbound_datas(application_state.database_context,
        OutboundDataFlag.TIP_FILTER_NOTIFICATIONS, OutboundDataFlag.TIP_FILTER_NOTIFICATIONS)
    assert len(pending_rows_3) == len(non_updated_ids)

    # Ensure that the set of non-dispatched rows are exactly the ones we did not mark as dispatched.
    pending_ids_3 = set(row.outbound_data_id for row in pending_rows_3
        if row.outbound_data_id is not None)
    assert pending_ids_3 == non_updated_ids

    # Test the outbound data delivery task works correctly.

    sleep_event = asyncio.Event()
    pytest_loop = asyncio.get_running_loop()
    approved_sleep_event = asyncio.Event()
    approved_sleep_event.set()

    async def fake_sleep(delay: float) -> None:
        sleep_loop = asyncio.get_running_loop()
        # Under the new Python regime your async objects get the active loop. This means you cannot
        # create objects for other loops, you have to create the objects within the loop you want
        # it for. But if you have multiple loops as we have here, now you have to do some other
        # stuff to make it work. It's a mess and a pain.
        if sleep_loop is pytest_loop:
            # Allow the test to block waiting for the caller to hit this event.
            sleep_event.set()
            sleep_event.clear()

            # Prevent infinite loops by blocking the caller.
            await approved_sleep_event.wait()
            # We call the copy of the original method before we mocked it.
            await asyncio_sleep(0)
        else:
            await asyncio_sleep(delay)

    sleep_mock.side_effect = fake_sleep

    task_ids = list[int]()
    future = application_state._create_outbound_delivery_task()
    try:
        for i in range(3):
            task_ids.append(pending_rows_3[i].outbound_data_id)
            current_time = pending_rows_3[i].date_created + 120.0
            await sleep_event.wait()
    finally:
        future.cancel()

    log_rows = sqlite_db.read_outbound_data_logs(application_state.database_context, task_ids)
    log_rows_by_id = dict[int, list[OutboundDataLogRow]]()
    for log_row in log_rows:
        assert log_row.outbound_data_id is not None
        log_id_rows = log_rows_by_id.setdefault(log_row.outbound_data_id, [])
        log_id_rows.append(log_row)

    # Each outbound data row will have been "tried" once for the creation, and once each for
    # each iteration above it was involved in. Each iteration is implicitly a failure.
    assert len(log_rows_by_id[pending_rows_3[0].outbound_data_id]) == 4
    assert len(log_rows_by_id[pending_rows_3[1].outbound_data_id]) == 3
    assert len(log_rows_by_id[pending_rows_3[2].outbound_data_id]) == 2

    # The first insert has the flags we gave it, the base flag for tip filters.
    first_data_log_flags = [ log_row.outbound_data_flags
        for log_row in log_rows_by_id[pending_rows_3[0].outbound_data_id] ]
    assert first_data_log_flags[0] == OutboundDataFlag.TIP_FILTER_NOTIFICATIONS

    # The subsequent inserts have the failure flag, that there is no account callback.
    no_callback_flags = OutboundDataFlag.TIP_FILTER_NOTIFICATIONS | \
        OutboundDataFlag.DISPATCH_NO_CALLBACK
    assert first_data_log_flags[1] == no_callback_flags
    assert first_data_log_flags[2] == no_callback_flags
    assert first_data_log_flags[3] == no_callback_flags

    await application_state.database_context.run_in_thread_async(
        sqlite_db.update_account_indexer_settings_write, pending_rows_3[0].account_id,
        { "tipFilterCallbackUrl": "127.0.0.1:63222" })

    # FAILURE CASE: Error establishing connection (or something close to it).
    def fake_request_error(*args: Any, **kwargs: Any) -> aiohttp.ClientResponse:
        raise aiohttp.ClientError()

    request_mock.side_effect = fake_request_error

    approved_sleep_event.clear()
    # NOTE(rt12) This task logs the exception from above and has no way of knowing pytest will
    #     spam it out during test execution. So the error logging is expected, ignore it.
    future = application_state._create_outbound_delivery_task()
    try:
        current_time = pending_rows_3[0].date_created + 120.0
        await sleep_event.wait()
    finally:
        future.cancel()

    # One more log entry for the first outbound data.
    log_rows = sqlite_db.read_outbound_data_logs(application_state.database_context,
        [ pending_rows_3[0].outbound_data_id ])
    assert len(log_rows) == 5
    # We are fudging the current time to retry only the first, so we need to get the original
    # entry from that time and the new entry from that time.
    log_rows = [ log_row for log_row in log_rows if log_row.date_created == current_time ]
    assert len(log_rows) == 2

    # We should find both the no callback and the exception cases not encountered.
    log_row_flags = { OutboundDataFlag(log_row.outbound_data_flags) for log_row in log_rows }
    assert log_row_flags == {
        OutboundDataFlag.TIP_FILTER_NOTIFICATIONS | OutboundDataFlag.DISPATCH_EXCEPTION,
        OutboundDataFlag.TIP_FILTER_NOTIFICATIONS | OutboundDataFlag.DISPATCH_NO_CALLBACK,
    }

    # FAILURE CASE: Response with non-OK status.
    def fake_request_status_404(*args: Any, **kwargs: Any) -> aiohttp.ClientResponse:
        mock = unittest.mock.Mock()
        mock.status = 404
        mock.reason = "not found"
        return mock

    request_mock.side_effect = fake_request_status_404

    future = application_state._create_outbound_delivery_task()
    try:
        current_time = pending_rows_3[0].date_created + 120.0
        await sleep_event.wait()
    finally:
        future.cancel()

    # One more log entry for the first outbound data.
    log_rows = sqlite_db.read_outbound_data_logs(application_state.database_context,
        [ pending_rows_3[0].outbound_data_id ])
    assert len(log_rows) == 6
    # We are fudging the current time to retry only the first, so we need to get the original
    # entry from that time and the new entry from that time.
    log_rows = [ log_row for log_row in log_rows if log_row.date_created == current_time ]
    assert len(log_rows) == 3

    # We should find both the no callback and the exception cases not encountered.
    log_row_flags = { OutboundDataFlag(log_row.outbound_data_flags) for log_row in log_rows }
    assert log_row_flags == {
        OutboundDataFlag.TIP_FILTER_NOTIFICATIONS | OutboundDataFlag.DISPATCH_EXCEPTION,
        OutboundDataFlag.TIP_FILTER_NOTIFICATIONS | OutboundDataFlag.DISPATCH_NO_CALLBACK,
        OutboundDataFlag.TIP_FILTER_NOTIFICATIONS,
    }

    new_log_row = [ log_row for log_row in log_rows
        if log_row.outbound_data_flags == OutboundDataFlag.TIP_FILTER_NOTIFICATIONS ][0]
    assert new_log_row.response_status_code == 404
    assert new_log_row.response_reason == "not found"

    # SUCCESS CASE: Response with OK status.
    def fake_request_status_200(*args: Any, **kwargs: Any) -> aiohttp.ClientResponse:
        mock = unittest.mock.Mock()
        mock.status = 200
        mock.reason = "found"
        return mock

    request_mock.side_effect = fake_request_status_200

    future = application_state._create_outbound_delivery_task()
    try:
        current_time = pending_rows_3[0].date_created + 120.0
        await sleep_event.wait()
    finally:
        future.cancel()

    # One more log entry for the first outbound data.
    log_rows = sqlite_db.read_outbound_data_logs(application_state.database_context,
        [ pending_rows_3[0].outbound_data_id ])
    assert len(log_rows) == 7
    # We are fudging the current time to retry only the first, so we need to get the original
    # entry from that time and the new entry from that time.
    log_rows = [ log_row for log_row in log_rows if log_row.date_created == current_time ]
    assert len(log_rows) == 4

    # We should find both the no callback and the exception cases not encountered.
    log_row_flags = { OutboundDataFlag(log_row.outbound_data_flags) for log_row in log_rows }
    assert log_row_flags == {
        OutboundDataFlag.TIP_FILTER_NOTIFICATIONS | OutboundDataFlag.DISPATCH_EXCEPTION,
        OutboundDataFlag.TIP_FILTER_NOTIFICATIONS | OutboundDataFlag.DISPATCH_NO_CALLBACK,
        OutboundDataFlag.TIP_FILTER_NOTIFICATIONS,
    }

    new_log_rows = [ log_row for log_row in log_rows
        if log_row.outbound_data_flags == OutboundDataFlag.TIP_FILTER_NOTIFICATIONS and
            log_row.response_status_code == 200 ]
    assert len(new_log_rows) == 1
    assert new_log_rows[0].response_status_code == 200
    assert new_log_rows[0].response_reason == "found"

    # Note that there will the be earlier rows we updated, as well as the later first row
    # we created for the "success" task test. We need to filter out the dud earlier rows.
    final_rows = [ data_row
        for data_row in sqlite_db.read_pending_outbound_datas(application_state.database_context,
            OutboundDataFlag.DISPATCHED_SUCCESSFULLY, OutboundDataFlag.DISPATCHED_SUCCESSFULLY)
        if data_row.outbound_data_id == new_log_rows[0].outbound_data_id ]
    assert len(final_rows) == 1


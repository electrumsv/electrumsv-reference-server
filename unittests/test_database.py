import os
import unittest.mock

from bitcoinx import PrivateKey, PublicKey
import pytest

from esv_reference_server.constants import IndexerPushdataRegistrationFlag
from esv_reference_server.application_state import ApplicationState
from esv_reference_server.sqlite_db import create_account, \
    create_indexer_filtering_registrations_pushdatas, \
    DatabaseStateModifiedError, delete_indexer_filtering_registrations_pushdatas, \
    read_indexer_filtering_registrations_pushdatas, prune_indexer_filtering, \
    update_indexer_filtering_registrations_pushdatas_flags
from esv_reference_server.types import TipFilterListEntry, TipFilterRegistrationEntry


PRIVATE_KEY_1 = PrivateKey.from_hex(
    "720f1987db69efa562b3dabd78e51f19bd8da76c70ad839b72b939f4071b144b")
PUBLIC_KEY_1: PublicKey = PRIVATE_KEY_1.public_key



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
    date_expires = (date_created_2 + duration_seconds)
    assert 1 == application_state.database_context.run_in_thread(prune_indexer_filtering,
        IndexerPushdataRegistrationFlag.NONE, IndexerPushdataRegistrationFlag.NONE,
        date_expires)

import os
import unittest.mock

import pytest

from esv_reference_server.constants import IndexerPushdataRegistrationFlag
from esv_reference_server.server import ApplicationState
from esv_reference_server.sqlite_db import create_indexer_filtering_registrations_pushdatas, \
    DatabaseStateModifiedError, delete_indexer_filtering_registrations_pushdatas, \
    read_indexer_filtering_registrations_pushdatas, prune_indexer_filtering, \
    update_indexer_filtering_registrations_pushdatas_flags

from . import conftest


@unittest.mock.patch('esv_reference_server.sqlite_db.time.time')
def test_filtering_pushdata_hash_registration(time: unittest.mock.Mock) -> None:
    app = conftest.app_reference
    assert app is not None

    app_state: ApplicationState = app["app_state"]
    account_id = app_state.temporary_account_id
    assert account_id is not None

    time.side_effect = lambda *args: 1.0

    # Create the first pushdata as a non-finalised registration.
    pushdata_hash_1 = os.urandom(32)
    pushdata_hashes = [ pushdata_hash_1 ]
    assert app_state.database_context.run_in_thread(
        create_indexer_filtering_registrations_pushdatas, account_id, pushdata_hashes)

    # That that update of pushdata flags errors if all provided pushdata are required to be updated
    # and not all are matched due to custom filtering.
    with pytest.raises(DatabaseStateModifiedError):
        app_state.database_context.run_in_thread(
            update_indexer_filtering_registrations_pushdatas_flags,
                account_id, pushdata_hashes,
                update_flags=IndexerPushdataRegistrationFlag.FINALISED,
                filter_flags=IndexerPushdataRegistrationFlag.FINALISED,
                require_all=True)

    # Finalise the first pushdata as fully registered on the indexer.
    app_state.database_context.run_in_thread(update_indexer_filtering_registrations_pushdatas_flags,
        account_id, pushdata_hashes, update_flags=IndexerPushdataRegistrationFlag.FINALISED)

    time.side_effect = lambda *args: 2.0

    # Creating anything in addition to something being registered at this point conflicts and fails.
    pushdata_hash_2 = os.urandom(32)
    assert not app_state.database_context.run_in_thread(
        create_indexer_filtering_registrations_pushdatas, account_id,
        [ pushdata_hash_1, pushdata_hash_2 ])

    app_state.database_context.run_in_thread(prune_indexer_filtering,
        IndexerPushdataRegistrationFlag.FINALISED, IndexerPushdataRegistrationFlag.FINALISED)

    # Recreate both pushdatas as non-finalised.
    pushdata_hash_2 = os.urandom(32)
    assert app_state.database_context.run_in_thread(
        create_indexer_filtering_registrations_pushdatas, account_id,
        [ pushdata_hash_1, pushdata_hash_2 ])

    # Only finalised pushdatas are read, and there are none.
    registered_pushdata_hashes = read_indexer_filtering_registrations_pushdatas(
        app_state.database_context, account_id,
        IndexerPushdataRegistrationFlag.FINALISED, IndexerPushdataRegistrationFlag.FINALISED)
    assert set(registered_pushdata_hashes) == set()

    app_state.database_context.run_in_thread(update_indexer_filtering_registrations_pushdatas_flags,
        account_id, [ pushdata_hash_1, pushdata_hash_2 ],
        update_flags=IndexerPushdataRegistrationFlag.FINALISED)

    # Now that the pushdatas are finalised ensure they are read.
    registered_pushdata_hashes = read_indexer_filtering_registrations_pushdatas(
        app_state.database_context, account_id,
        IndexerPushdataRegistrationFlag.FINALISED, IndexerPushdataRegistrationFlag.FINALISED)
    assert set(registered_pushdata_hashes) == { pushdata_hash_1, pushdata_hash_2 }

    # Delete one pushdata leaving the other in place.
    app_state.database_context.run_in_thread(delete_indexer_filtering_registrations_pushdatas,
        account_id, [ pushdata_hash_1 ])

    # Check that the first was deleted and the second remains.
    registered_pushdata_hashes = read_indexer_filtering_registrations_pushdatas(
        app_state.database_context, account_id,
        IndexerPushdataRegistrationFlag.FINALISED, IndexerPushdataRegistrationFlag.FINALISED)
    assert registered_pushdata_hashes == [ pushdata_hash_2 ]

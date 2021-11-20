# Open BSV License version 3
# Copyright (c) 2021 Bitcoin Association
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# 1 - The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 2 - The Software, and any software that is derived from the Software or parts thereof,
# can only be used on the Bitcoin SV blockchains. The Bitcoin SV blockchains are defined,
# for purposes of this license, as the Bitcoin blockchain containing block height #556767
# with the hash "000000000000000001d956714215d96ffc00e0afda4cd0a96c96f8d802b1662b" and
# that contains the longest persistent chain of blocks that are accepted by the un-modified
# Software, as well as the test blockchains that contain blocks that are accepted by the
# un-modified Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

from __future__ import annotations
import os
from typing import List, NamedTuple, Tuple, Optional

from bitcoinx import Bitcoin, Ops, P2PKH_Address, P2PK_Output, P2MultiSig_Output, PrivateKey, \
    PublicKey, Script, SigHash, Tx, TxInput, TxOutput
import pytest

from esv_reference_server.constants import AccountFlags, ChannelState
from esv_reference_server.keys import create_regtest_server_keys, ServerKeys
from esv_reference_server.payment_channels import _calculate_transaction_fee, \
    _sign_contract_transaction_input, BrokenChannelError, generate_payment_private_key, \
    generate_payment_public_key, InvalidTransactionError, MINIMUM_CHANNEL_PAYMENT_VALUE, \
    MINIMUM_FUNDING_VALUE, MINIMUM_REFUND_SECONDS, MAXIMUM_REFUND_SECONDS, PaymentChannelError, \
    process_contract_close_async, process_contract_update_async, process_funding_script,\
    process_funding_transaction_async, process_refund_contract_transaction, SAFE_DUST_VALUE

from esv_reference_server.sqlite_db import AccountMetadata, ChannelRow


PRIVATE_KEY_1 = PrivateKey.from_hex(
    "720f1987db69efa562b3dabd78e51f19bd8da76c70ad839b72b939f4071b144b")
PUBLIC_KEY_1 = PRIVATE_KEY_1.public_key

PRIVATE_KEY_2 = PrivateKey.from_hex(
    "8d776373012ed183b5d45dc1e543637a8c7e075de964826fd1f85ebbc6759b58")
PUBLIC_KEY_2 = PRIVATE_KEY_2.public_key

CLIENT_REFUND_KEY_MESSAGE_HEX = "56c681feacca020cb76435bcd075290fb890d35d4044c76f8ece5e4bb4ffe450"
CLIENT_REFUND_KEY = PUBLIC_KEY_1.add(bytes.fromhex(CLIENT_REFUND_KEY_MESSAGE_HEX))

SERVER_PAYMENT_INDEX = 1
SERVER_PAYMENT_PRIVATE_KEY = generate_payment_private_key(
    create_regtest_server_keys().identity_private_key, PUBLIC_KEY_1.to_bytes(),
        SERVER_PAYMENT_INDEX)
SERVER_PAYMENT_KEY = generate_payment_public_key(
    create_regtest_server_keys().identity_public_key, PUBLIC_KEY_1.to_bytes(),
        SERVER_PAYMENT_INDEX)


def test_process_funding_script__P2PK_fails() -> None:
    p2pk_output = P2PK_Output(PUBLIC_KEY_1, Bitcoin)
    assert process_funding_script(p2pk_output.to_script_bytes(), PUBLIC_KEY_1) is None


def test_process_funding_script__P2PKH_fails() -> None:
    p2pkh_address = P2PKH_Address(PUBLIC_KEY_1.hash160(), Bitcoin)
    assert process_funding_script(p2pkh_address.to_script_bytes(), PUBLIC_KEY_1) is None


def test_process_funding_script__P2MultiSig() -> None:
    p2ms_output = P2MultiSig_Output([ PUBLIC_KEY_1, PUBLIC_KEY_2 ], 2)
    script = process_funding_script(p2ms_output.to_script_bytes(), PUBLIC_KEY_1.to_bytes())
    assert script is not None
    assert script == p2ms_output


def _make_funding_transaction(p2ms_output: P2MultiSig_Output, funding_value: int) -> Tx:
    prev_hash = bytes.fromhex("6ff22bbf85a0f32df727d1dac65e6f7be42a0a4a862dc3f4b56ad9d4d0f76bb9")
    tx_input = TxInput(prev_hash, 0, Script(), 0xFFFFFFFF)
    tx_output = TxOutput(funding_value, p2ms_output.to_script())
    return Tx(2, [tx_input], [tx_output], 0)


def _make_refund_transaction(funding_transaction_hash: bytes, delivery_time: int,
        funding_value: int) -> Tx:
    tx_input = TxInput(funding_transaction_hash, 0, Script(), 0)
    tx_output = TxOutput(funding_value,
        P2PKH_Address(CLIENT_REFUND_KEY.hash160(), Bitcoin).to_script())
    return Tx(2, [tx_input], [tx_output], delivery_time + MINIMUM_REFUND_SECONDS)


def _make_client_contract_signature(refund_transaction: Tx, p2ms_output: P2MultiSig_Output,
        funding_value: int, private_key: Optional[PrivateKey]=None) -> bytes:
    if private_key is None:
        private_key = PRIVATE_KEY_1
    client_contract_signature_bytes = _sign_contract_transaction_input(refund_transaction,
        p2ms_output.to_script_bytes(),
        funding_value, private_key,
        SigHash(SigHash.SINGLE | SigHash.ANYONE_CAN_PAY | SigHash.FORKID))
    refund_transaction.inputs[0].script_sig = \
        Script() << Ops.OP_0 << client_contract_signature_bytes << bytes(32)
    return client_contract_signature_bytes


class LooseData(NamedTuple):
    delivery_time: int
    funding_value: int
    p2ms_output: P2MultiSig_Output
    server_keys: ServerKeys


def _make_loose_data() -> LooseData:
    return LooseData(
        delivery_time = 100,
        funding_value = MINIMUM_FUNDING_VALUE,
        p2ms_output = P2MultiSig_Output([ PUBLIC_KEY_1, SERVER_PAYMENT_KEY ], 2),
        server_keys = create_regtest_server_keys()
    )


def _make_database_rows(*, channel_state: ChannelState,
        funding_transaction_hash: Optional[bytes]=None) \
            -> Tuple[LooseData, AccountMetadata, ChannelRow]:
    loose_data = _make_loose_data()

    contract_transaction: Optional[Tx] = None
    if funding_transaction_hash is not None:
        contract_transaction = _make_refund_transaction(funding_transaction_hash,
            loose_data.delivery_time, loose_data.funding_value)
        _make_client_contract_signature(contract_transaction, loose_data.p2ms_output,
            loose_data.funding_value)

    account_id = 1
    channel_id = 1
    db_payment_key_index = SERVER_PAYMENT_INDEX
    db_payment_key_bytes = SERVER_PAYMENT_KEY.to_bytes()
    db_funding_transaction_hash = funding_transaction_hash
    db_funding_output_script_bytes = loose_data.p2ms_output.to_script_bytes() \
        if channel_state == ChannelState.CONTRACT_OPEN else None
    db_funding_value = loose_data.funding_value \
        if channel_state in (ChannelState.REFUND_ESTABLISHED, ChannelState.CONTRACT_OPEN) else \
        0
    db_client_payment_key_bytes = PUBLIC_KEY_1.to_bytes() \
        if channel_state in (ChannelState.REFUND_ESTABLISHED, ChannelState.CONTRACT_OPEN) else \
        None
    db_contract_transaction_bytes = contract_transaction.to_bytes() \
        if contract_transaction is not None else None
    db_refund_signature_bytes = bytes.fromhex(
        "3044022031b0e1038dea89e8ebb1ef01c6191f7a24f38779e8178985f59fcd512ed64519022043179fc7b"
        "eff4d05eab727547a9e072334f5a4ed26e4ab6551e7c3a30cb4f4a841") \
        if channel_state in (ChannelState.REFUND_ESTABLISHED, ChannelState.CONTRACT_OPEN) else \
        None
    db_refund_value = loose_data.funding_value \
        if channel_state == ChannelState.CONTRACT_OPEN else 0
    db_refund_sequence = 0
    db_prepaid_balance_value = 0
    db_spent_balance_value = 0

    account_metadata = AccountMetadata(PUBLIC_KEY_1.to_bytes(), "api_key", channel_id,
        AccountFlags.MID_CREATION, 1)
    channel_row = ChannelRow(account_id, channel_id, channel_state,
        db_payment_key_index, db_payment_key_bytes, db_funding_transaction_hash,
        db_funding_output_script_bytes, db_funding_value, db_client_payment_key_bytes,
        db_contract_transaction_bytes, db_refund_signature_bytes, db_refund_value,
        db_refund_sequence, db_prepaid_balance_value, db_spent_balance_value)
    return loose_data, account_metadata, channel_row


@pytest.mark.parametrize("channel_state", (
    ChannelState.INVALID,
    ChannelState.CONTRACT_OPEN,
    ChannelState.CLOSED_INVALID_FUNDING_TRANSACTION,
    ChannelState.CLOSED_BROADCASTING_FUNDING_TRANSACTION))
def test_process_refund_contract_transaction__invalid_state(channel_state) -> None:
    loose_data, account_metadata, channel_row = \
        _make_database_rows(channel_state=channel_state)

    transaction = os.urandom(10)
    with pytest.raises(AssertionError) as exc_info:
        process_refund_contract_transaction(transaction, loose_data.delivery_time,
            loose_data.funding_value, loose_data.p2ms_output, loose_data.server_keys,
            account_metadata, channel_row)
    assert exc_info.value.args[0] == "Invalid channel state"


def test_process_refund_contract_transaction__corrupt_transaction() -> None:
    loose_data, account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.PAYMENT_KEY_DISPENSED)

    transaction = os.urandom(10)
    with pytest.raises(InvalidTransactionError) as exc_info:
        process_refund_contract_transaction(transaction, loose_data.delivery_time,
            loose_data.funding_value, loose_data.p2ms_output, loose_data.server_keys,
            account_metadata, channel_row)
    assert exc_info.value.args[0] == "Contract transaction is corrupt"


@pytest.mark.parametrize("tx_inputs", (
    # Edge case less than one input / no inputs.
    [],
    # Edge case more than one input / two inputs.
    [TxInput(os.urandom(32), 0, Script(), 0xFFFFFFFF),
    TxInput(os.urandom(32), 0, Script(), 0xFFFFFFFF)]))
def test_process_refund_contract_transaction__incorrect_number_of_inputs(tx_inputs) -> None:
    loose_data, account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.PAYMENT_KEY_DISPENSED)

    transaction = Tx(2, tx_inputs, [], 0).to_bytes()
    with pytest.raises(InvalidTransactionError) as exc_info:
        process_refund_contract_transaction(transaction, loose_data.delivery_time,
            loose_data.funding_value, loose_data.p2ms_output, loose_data.server_keys,
            account_metadata, channel_row)
    assert exc_info.value.args[0] == "Only the funding input should be present"


@pytest.mark.parametrize("sequence", (
    # Edge case more than 0 (the next one).
    1,
    # Edge case extreme final input.
    0xFFFFFFFF))
def test_process_refund_contract_transaction__incorrect_input_sequence(sequence) -> None:
    loose_data, account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.PAYMENT_KEY_DISPENSED)

    transaction = Tx(2, [TxInput(os.urandom(32), 0, Script(), sequence)], [], 0).to_bytes()
    with pytest.raises(InvalidTransactionError) as exc_info:
        process_refund_contract_transaction(transaction, loose_data.delivery_time,
            loose_data.funding_value, loose_data.p2ms_output, loose_data.server_keys,
            account_metadata, channel_row)
    assert exc_info.value.args[0] == "The initial funding input nSequence value should be 0"


@pytest.mark.parametrize("locktime_seconds,error_message", (
    (MINIMUM_REFUND_SECONDS, "Only one refund output should be present"),  # The next error.
    # Edge case less than the minimum.
    (MINIMUM_REFUND_SECONDS - 1, "Locktime must be around 86400 seconds"), # This error.
    # Edge case more than the maximum.
    (MAXIMUM_REFUND_SECONDS + 1, "Locktime must be around 86400 seconds"), # This error.
    (MAXIMUM_REFUND_SECONDS, "Only one refund output should be present"))) # The next error
def test_process_refund_contract_transaction__incorrect_locktime(locktime_seconds: int,
        error_message: str) -> None:
    loose_data, account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.PAYMENT_KEY_DISPENSED)

    transaction = Tx(2, [TxInput(os.urandom(32), 0, Script(), 0)], [],
        loose_data.delivery_time + locktime_seconds).to_bytes()
    with pytest.raises(InvalidTransactionError) as exc_info:
        process_refund_contract_transaction(transaction, loose_data.delivery_time,
            loose_data.funding_value, loose_data.p2ms_output, loose_data.server_keys,
            account_metadata, channel_row)
    assert exc_info.value.args[0] == error_message


@pytest.mark.parametrize("tx_outputs,error_message", (
    ([],
        "Only one refund output should be present"),        # This error.
    ([ TxOutput(100, Script()), TxOutput(100, Script()) ],
        "Only one refund output should be present"),        # This error.
    ([ TxOutput(100, Script()) ],
        "Channel funding value"),                           # The next error.
    ))
def test_process_refund_contract_transaction__incorrect_outputs(tx_outputs: List[TxOutput],
        error_message: str) -> None:
    loose_data, account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.PAYMENT_KEY_DISPENSED)
    # Ensure we trigger "the next error" if we pass "this error".
    funding_value = MINIMUM_FUNDING_VALUE - 1

    transaction = Tx(2, [TxInput(os.urandom(32), 0, Script(), 0)], tx_outputs,
        loose_data.delivery_time + MINIMUM_REFUND_SECONDS).to_bytes()
    with pytest.raises(InvalidTransactionError) as exc_info:
        process_refund_contract_transaction(transaction, loose_data.delivery_time,
            funding_value, loose_data.p2ms_output, loose_data.server_keys, account_metadata,
            channel_row)
    assert exc_info.value.args[0].startswith(error_message)


@pytest.mark.parametrize("funding_value,error_message", (
    (0,
        "Channel funding value"),                           # This error.
    (MINIMUM_FUNDING_VALUE - 1,
        "Channel funding value"),                           # This error.
    (MINIMUM_FUNDING_VALUE,
        "Refunded value higher than funded value"),         # The next error.
    ))
def test_process_refund_contract_transaction__incorrect_funding_value(funding_value: int,
        error_message: str) -> None:
    loose_data, account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.PAYMENT_KEY_DISPENSED)

    transaction = Tx(2, [TxInput(os.urandom(32), 0, Script(), 0)],
        [TxOutput(MINIMUM_FUNDING_VALUE * 2, Script())],
        loose_data.delivery_time + MINIMUM_REFUND_SECONDS).to_bytes()
    with pytest.raises(InvalidTransactionError) as exc_info:
        process_refund_contract_transaction(transaction, loose_data.delivery_time,
            funding_value, loose_data.p2ms_output, loose_data.server_keys, account_metadata,
            channel_row)
    assert exc_info.value.args[0].startswith(error_message)


@pytest.mark.parametrize("refund_value,error_message", (
    (MINIMUM_FUNDING_VALUE + 1,
        "Refunded value higher than funded value"),         # This error.
    (MINIMUM_FUNDING_VALUE,
        "Funding output script lacks server payment key"),  # The next error.
    ))
def test_process_refund_contract_transaction__refund_value_too_high(refund_value: int,
        error_message: str) -> None:
    loose_data, account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.PAYMENT_KEY_DISPENSED)
    # Ensure we trigger "the next error" if we pass "this error".
    p2ms_output = P2MultiSig_Output([ loose_data.p2ms_output.public_keys[0],
        PrivateKey.from_random().public_key], loose_data.p2ms_output.threshold)

    transaction = Tx(2, [TxInput(os.urandom(32), 0, Script(), 0)],
        [TxOutput(refund_value, Script())],
        loose_data.delivery_time + MINIMUM_REFUND_SECONDS).to_bytes()
    with pytest.raises(InvalidTransactionError) as exc_info:
        process_refund_contract_transaction(transaction, loose_data.delivery_time,
            loose_data.funding_value, p2ms_output, loose_data.server_keys, account_metadata,
            channel_row)
    assert exc_info.value.args[0].startswith(error_message)


@pytest.mark.parametrize("payment_key,error_message", (
    (PrivateKey.from_random().public_key,
        "Funding output script lacks server payment key"),         # This error.
    (SERVER_PAYMENT_KEY,
        "Invalid refund spend stack size"),                        # The next error.
    ))
def test_process_refund_contract_transaction__incorrect_funding_output_key(payment_key: PublicKey,
        error_message: str) -> None:
    loose_data, account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.PAYMENT_KEY_DISPENSED)
    # Ensure we trigger "the next error" if we pass "this error".
    p2ms_output = P2MultiSig_Output([ loose_data.p2ms_output.public_keys[0],
        payment_key], loose_data.p2ms_output.threshold)

    transaction = Tx(2, [TxInput(os.urandom(32), 0, Script(), 0)],
        [TxOutput(MINIMUM_FUNDING_VALUE, Script())],
        loose_data.delivery_time + MINIMUM_REFUND_SECONDS).to_bytes()
    with pytest.raises(PaymentChannelError) as exc_info:
        process_refund_contract_transaction(transaction, loose_data.delivery_time,
            loose_data.funding_value, p2ms_output, loose_data.server_keys, account_metadata,
            channel_row)
    assert exc_info.value.args[0].startswith(error_message)


# TODO(unittest) ""


@pytest.mark.parametrize("script,error_message", (
    (Script() << Ops.OP_PUSHDATA4,
        "Truncated refund input script"),                 # This error.
    ))
def test_process_refund_contract_transaction__invalid_input_script(script: Script,
        error_message: str) -> None:
    loose_data, account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.PAYMENT_KEY_DISPENSED)
    # Ensure we trigger "the next error" if we pass "this error".

    transaction = Tx(2, [TxInput(os.urandom(32), 0, script, 0)],
        [TxOutput(MINIMUM_FUNDING_VALUE, Script())],
        loose_data.delivery_time + MINIMUM_REFUND_SECONDS).to_bytes()
    with pytest.raises(PaymentChannelError) as exc_info:
        process_refund_contract_transaction(transaction, loose_data.delivery_time,
            loose_data.funding_value, loose_data.p2ms_output, loose_data.server_keys,
            account_metadata, channel_row)
    assert exc_info.value.args[0].startswith(error_message)


@pytest.mark.parametrize("script,error_message", (
    (Script(),
        "Invalid refund spend stack size"),                 # This error.
    (Script() << os.urandom(32),
        "Invalid refund spend stack size"),                 # This error.
    (Script() << Ops.OP_0 << os.urandom(32) << os.urandom(32),
        "Invalid client refund signature"),                 # The next error.
    ))
def test_process_refund_contract_transaction__incorrect_signature_count(script: Script,
        error_message: str) -> None:
    loose_data, account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.PAYMENT_KEY_DISPENSED)
    # Ensure we trigger "the next error" if we pass "this error".

    transaction = Tx(2, [TxInput(os.urandom(32), 0, script, 0)],
        [TxOutput(MINIMUM_FUNDING_VALUE, Script())],
        loose_data.delivery_time + MINIMUM_REFUND_SECONDS).to_bytes()
    with pytest.raises(PaymentChannelError) as exc_info:
        process_refund_contract_transaction(transaction, loose_data.delivery_time,
            loose_data.funding_value, loose_data.p2ms_output, loose_data.server_keys,
            account_metadata, channel_row)
    assert exc_info.value.args[0].startswith(error_message)


@pytest.mark.parametrize("signature_bytes,error_message", (
    (os.urandom(32),
        "Invalid client refund signature"),                 # This error.
    (b"marker",
        "Invalid sighash for client refund signature"),     # The next error.
    ))
def test_process_refund_contract_transaction__invalid_signature(signature_bytes: bytes,
        error_message: str) -> None:
    loose_data, account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.PAYMENT_KEY_DISPENSED)
    # Ensure we trigger "the next error" if we pass "this error".
    script = Script() << Ops.OP_0 << signature_bytes << b"\0"
    outgoing_script = P2PKH_Address(os.urandom(20), Bitcoin)

    transaction = Tx(2, [TxInput(os.urandom(32), 0, script, 0)],
        [TxOutput(MINIMUM_FUNDING_VALUE, outgoing_script.to_script())],
        loose_data.delivery_time + MINIMUM_REFUND_SECONDS)

    if signature_bytes == b"marker":
        signature_bytes = _sign_contract_transaction_input(transaction,
            loose_data.p2ms_output.to_script_bytes(),
            loose_data.funding_value, PRIVATE_KEY_1)
        transaction.inputs[0].script_sig = Script() << Ops.OP_0 << signature_bytes << b"\0"

    with pytest.raises(PaymentChannelError) as exc_info:
        process_refund_contract_transaction(transaction.to_bytes(), loose_data.delivery_time,
            loose_data.funding_value, loose_data.p2ms_output, loose_data.server_keys,
            account_metadata, channel_row)
    assert exc_info.value.args[0].startswith(error_message)


def test_process_refund_contract_transaction() -> None:
    loose_data, account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.PAYMENT_KEY_DISPENSED)

    funding_transaction = _make_funding_transaction(loose_data.p2ms_output,
        loose_data.funding_value)
    funding_transaction_hash = funding_transaction.hash()
    transaction = _make_refund_transaction(funding_transaction_hash, loose_data.delivery_time,
        loose_data.funding_value)
    _make_client_contract_signature(transaction, loose_data.p2ms_output,
        loose_data.funding_value)
    # signature_bytes = _sign_contract_transaction_input(transaction,
    #     loose_data.p2ms_output.to_script_bytes(),
    #     loose_data.funding_value, PRIVATE_KEY_1,
    #     SigHash(SigHash.SINGLE | SigHash.ANYONE_CAN_PAY | SigHash.FORKID))
    # transaction.inputs[0].script_sig = Script() << signature_bytes << b"\0"

    client_refund_payment_key_bytes, server_refund_signature_bytes = \
        process_refund_contract_transaction(transaction.to_bytes(), loose_data.delivery_time,
            loose_data.funding_value, loose_data.p2ms_output, loose_data.server_keys,
            account_metadata, channel_row)

    # Verify the client refund key is correct.
    assert client_refund_payment_key_bytes == PUBLIC_KEY_1.to_bytes()

    # Verify the server refund signature is correct.
    signature_hash = transaction.signature_hash(0, loose_data.funding_value,
        loose_data.p2ms_output.to_script_bytes(), SigHash(SigHash.ALL | SigHash.FORKID))
    refund_private_key = generate_payment_private_key(loose_data.server_keys.identity_private_key,
        account_metadata.public_key_bytes, channel_row.payment_key_index)
    assert refund_private_key.public_key.verify_der_signature(server_refund_signature_bytes[:-1],
        signature_hash, None)


@pytest.mark.asyncio
async def test_process_funding_transaction_async__incorrect_channel_state() -> None:
    _loose_data, _account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.PAYMENT_KEY_DISPENSED)

    with pytest.raises(AssertionError) as exc_info:
        await process_funding_transaction_async(b"", channel_row)
    assert exc_info.value.args[0].startswith("Invalid channel state")


@pytest.mark.asyncio
async def test_process_funding_transaction_async__missing_refund_signature_bytes() -> None:
    _loose_data, _account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.REFUND_ESTABLISHED)
    # Contrive this unlikely problem.
    channel_row = channel_row._replace(refund_signature_bytes=None)

    with pytest.raises(AssertionError) as exc_info:
        await process_funding_transaction_async(b"", channel_row)
    assert exc_info.value.args[0].startswith("Missing 'refund_signature_bytes' state")


@pytest.mark.asyncio
async def test_process_funding_transaction_async__incorrect_funding_transaction_hash() -> None:
    loose_data = _make_loose_data()
    funding_transaction = _make_funding_transaction(loose_data.p2ms_output,
        loose_data.funding_value)
    _loose_data, _account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.REFUND_ESTABLISHED,
            funding_transaction_hash=funding_transaction.hash())

    with pytest.raises(BrokenChannelError) as exc_info:
        await process_funding_transaction_async(os.urandom(32), channel_row)
    assert exc_info.value.args[0].startswith(
        "Funding transaction hash does not match refund prev_hash")


@pytest.mark.asyncio
async def test_process_funding_transaction_async__corrupt_contract() -> None:
    loose_data = _make_loose_data()
    funding_transaction = _make_funding_transaction(loose_data.p2ms_output,
        loose_data.funding_value)
    _loose_data, _account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.REFUND_ESTABLISHED,
            funding_transaction_hash=funding_transaction.hash())
    # Contrive this unlikely problem.
    channel_row = channel_row._replace(contract_transaction_bytes=os.urandom(32))

    with pytest.raises(BrokenChannelError) as exc_info:
        await process_funding_transaction_async(funding_transaction.to_bytes(), channel_row)
    assert exc_info.value.args[0].startswith("Corrupt contract transaction")


@pytest.mark.asyncio
async def test_process_funding_transaction_async__incorrect_refund_scriptsig() -> None:
    loose_data = _make_loose_data()
    funding_transaction = _make_funding_transaction(loose_data.p2ms_output,
        loose_data.funding_value)
    _loose_data, _account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.REFUND_ESTABLISHED,
            funding_transaction_hash=funding_transaction.hash())
    # Contrive this problem by breaking the contract input script_sig.
    contract_transaction = Tx.from_bytes(channel_row.contract_transaction_bytes)
    contract_transaction.inputs[0].script_sig = Script()
    channel_row = channel_row._replace(contract_transaction_bytes=contract_transaction.to_bytes())

    with pytest.raises(BrokenChannelError) as exc_info:
        await process_funding_transaction_async(funding_transaction.to_bytes(), channel_row)
    assert exc_info.value.args[0].startswith("Invalid refund spend stack size")


@pytest.mark.asyncio
async def test_process_funding_transaction_async__nonfinal_funding_inputs() -> None:
    loose_data = _make_loose_data()
    funding_transaction = _make_funding_transaction(loose_data.p2ms_output,
        loose_data.funding_value)
    _loose_data, _account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.REFUND_ESTABLISHED,
            funding_transaction_hash=funding_transaction.hash())
    # Contrive this problem by modifying the funding transaction sequence.
    funding_transaction.inputs[0].sequence = 0
    channel_row = channel_row._replace(funding_transaction_hash=funding_transaction.hash())

    with pytest.raises(BrokenChannelError) as exc_info:
        await process_funding_transaction_async(funding_transaction.to_bytes(), channel_row)
    assert exc_info.value.args[0].startswith("Funding transaction inputs must all be final")


@pytest.mark.asyncio
async def test_process_funding_transaction_async__incorrect_funding_transaction_value() -> None:
    loose_data = _make_loose_data()
    funding_transaction = _make_funding_transaction(loose_data.p2ms_output,
        loose_data.funding_value)
    # Contrive this problem by modifying the funding transaction output value.
    funding_transaction.outputs[0].value = 10
    _loose_data, _account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.REFUND_ESTABLISHED,
            funding_transaction_hash=funding_transaction.hash())

    with pytest.raises(BrokenChannelError) as exc_info:
        await process_funding_transaction_async(funding_transaction.to_bytes(), channel_row)
    assert exc_info.value.args[0].startswith("Funding transaction output value mismatch")


@pytest.mark.asyncio
async def test_process_funding_transaction_async__incorrect_funding_transaction_script() -> None:
    loose_data = _make_loose_data()
    funding_transaction = _make_funding_transaction(loose_data.p2ms_output,
        loose_data.funding_value)
    # Contrive this problem by modifying the funding transaction output value.
    funding_transaction.outputs[0].script_pubkey = \
        P2PKH_Address(os.urandom(20), Bitcoin).to_script()
    _loose_data, _account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.REFUND_ESTABLISHED,
            funding_transaction_hash=funding_transaction.hash())

    with pytest.raises(BrokenChannelError) as exc_info:
        await process_funding_transaction_async(funding_transaction.to_bytes(), channel_row)
    assert exc_info.value.args[0].startswith("Funding transaction output script mismatch")


@pytest.mark.asyncio
async def test_process_funding_transaction_async__non_der_contract_signature() -> None:
    loose_data = _make_loose_data()
    funding_transaction = _make_funding_transaction(loose_data.p2ms_output,
        loose_data.funding_value)
    _loose_data, _account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.REFUND_ESTABLISHED,
            funding_transaction_hash=funding_transaction.hash())

    # Contrive this problem by breaking the contract input script_sig.
    contract_transaction = Tx.from_bytes(channel_row.contract_transaction_bytes)
    contract_transaction.inputs[0].script_sig = Script() << Ops.OP_0 << bytes(32) << bytes(32)
    channel_row = channel_row._replace(contract_transaction_bytes=contract_transaction.to_bytes())

    with pytest.raises(BrokenChannelError) as exc_info:
        await process_funding_transaction_async(funding_transaction.to_bytes(), channel_row)
    assert exc_info.value.args[0].startswith(
        "Funding transaction script error 'signature does not follow strict DER encoding'")


@pytest.mark.asyncio
async def test_process_funding_transaction_async__wrong_contract_signature() -> None:
    loose_data = _make_loose_data()
    funding_transaction = _make_funding_transaction(loose_data.p2ms_output,
        loose_data.funding_value)
    _loose_data, _account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.REFUND_ESTABLISHED,
            funding_transaction_hash=funding_transaction.hash())

    # Contrive this problem by breaking the contract input script_sig.
    contract_transaction = Tx.from_bytes(channel_row.contract_transaction_bytes)
    private_key_1 = PrivateKey.from_random()
    client_signature_bytes = _make_client_contract_signature(contract_transaction,
        loose_data.p2ms_output, loose_data.funding_value, private_key=private_key_1)
    contract_transaction.inputs[0].script_sig = Script() << Ops.OP_0 \
        << client_signature_bytes << client_signature_bytes
    channel_row = channel_row._replace(contract_transaction_bytes=contract_transaction.to_bytes())

    with pytest.raises(BrokenChannelError) as exc_info:
        await process_funding_transaction_async(funding_transaction.to_bytes(), channel_row)
    assert exc_info.value.args[0].startswith(
        "Funding transaction script error 'signature check failed on a non-null signature'")


@pytest.mark.asyncio
async def test_process_funding_transaction_async__valid() -> None:
    loose_data = _make_loose_data()
    funding_transaction = _make_funding_transaction(loose_data.p2ms_output,
        loose_data.funding_value)
    _loose_data, _account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.REFUND_ESTABLISHED,
            funding_transaction_hash=funding_transaction.hash())

    funding_output_script_bytes = \
        await process_funding_transaction_async(funding_transaction.to_bytes(), channel_row)
    assert funding_output_script_bytes == loose_data.p2ms_output.to_script_bytes()


@pytest.mark.parametrize("refund_delta,error_message", (
    (MINIMUM_CHANNEL_PAYMENT_VALUE - 1,
        "Refund delta below minimum payment value"),        # This minimum payment error.
    (12345678,                                              # Marker for dust value.
        "Refund <= 546 (safe dust value)"),                 # This dust error.
    (12345677,                                              # Marker for just above dust.
        "Funding transaction signature invalid"),           # The next error.
    (MINIMUM_CHANNEL_PAYMENT_VALUE,
        "Funding transaction signature invalid"),           # The next error.
    ))
@pytest.mark.asyncio
async def test_process_contract_update_async__refund_value_edge_cases(refund_delta: int,
        error_message: str) -> None:
    loose_data = _make_loose_data()

    if refund_delta == 12345678:
        refund_delta = loose_data.funding_value - SAFE_DUST_VALUE
    elif refund_delta == 12345677:
        refund_delta = loose_data.funding_value - SAFE_DUST_VALUE - 1

    funding_transaction = _make_funding_transaction(loose_data.p2ms_output,
        loose_data.funding_value)
    _loose_data, _account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.CONTRACT_OPEN,
            funding_transaction_hash=funding_transaction.hash())

    contract_transaction = Tx.from_bytes(channel_row.contract_transaction_bytes)
    new_refund_value = loose_data.funding_value - refund_delta
    contract_transaction.outputs[0].value = new_refund_value
    new_refund_signature = _make_client_contract_signature(contract_transaction,
        loose_data.p2ms_output, loose_data.funding_value)
    with pytest.raises(BrokenChannelError) as exc_info:
        await process_contract_update_async(new_refund_signature, new_refund_value, channel_row)
    assert exc_info.value.args[0].startswith(error_message)


@pytest.mark.asyncio
async def test_process_contract_update_async__valid() -> None:
    loose_data = _make_loose_data()
    funding_transaction = _make_funding_transaction(loose_data.p2ms_output,
        loose_data.funding_value)
    _loose_data, _account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.CONTRACT_OPEN,
            funding_transaction_hash=funding_transaction.hash())

    # The contrived test state here is as if the client we iterating it's local initial refund
    # contract transaction as it expects the server to be iterating theirs.
    contract_transaction = Tx.from_bytes(channel_row.contract_transaction_bytes)
    client_new_sequence = 1
    client_new_refund_value = loose_data.funding_value - MINIMUM_CHANNEL_PAYMENT_VALUE
    contract_transaction.inputs[0].sequence = client_new_sequence
    contract_transaction.outputs[0].value = client_new_refund_value
    new_refund_signature = _make_client_contract_signature(contract_transaction,
        loose_data.p2ms_output, loose_data.funding_value)

    server_new_sequence = await process_contract_update_async(new_refund_signature,
        client_new_refund_value, channel_row)
    assert server_new_sequence == client_new_sequence


@pytest.mark.asyncio
async def test_process_contract_close_async__valid() -> None:
    loose_data = _make_loose_data()
    funding_transaction = _make_funding_transaction(loose_data.p2ms_output,
        loose_data.funding_value)
    _loose_data, account_metadata, channel_row = \
        _make_database_rows(channel_state=ChannelState.CONTRACT_OPEN,
            funding_transaction_hash=funding_transaction.hash())

    # The contrived test state here is as if the client we iterating it's local initial refund
    # contract transaction as it expects the server to be iterating theirs.
    client_contract_transaction = Tx.from_bytes(channel_row.contract_transaction_bytes)
    client_new_refund_value = loose_data.funding_value - MINIMUM_CHANNEL_PAYMENT_VALUE * 3
    client_contract_transaction.inputs[0].sequence = 0xFFFFFFFF
    client_contract_transaction.outputs[0].value = client_new_refund_value
    new_client_contract_signature_bytes = _make_client_contract_signature(
        client_contract_transaction, loose_data.p2ms_output, loose_data.funding_value)

    channel_row = channel_row._replace(refund_sequence=99)

    server_contract_transaction_bytes = await process_contract_close_async(
        new_client_contract_signature_bytes, client_new_refund_value, loose_data.server_keys,
        account_metadata, channel_row)
    server_contract_transaction = Tx.from_bytes(server_contract_transaction_bytes)
    script_data = list(server_contract_transaction.inputs[0].script_sig.ops())
    assert script_data[1] == new_client_contract_signature_bytes

    # We will update the client contract transaction with the differences and see what is
    # different. It should just be the lacking server signature and the server output.
    client_contract_transaction.inputs[0].script_sig = \
        Script() << Ops.OP_0 << new_client_contract_signature_bytes << script_data[2]
    client_contract_transaction.outputs.append(server_contract_transaction.outputs[1])
    assert server_contract_transaction_bytes == client_contract_transaction.to_bytes()


def test__calculate_transaction_fee() -> None:
    output = P2PKH_Address(os.urandom(20), Bitcoin)
    tx_input = TxInput(os.urandom(32), 0, Script() << os.urandom(32), 10)
    tx_output = TxOutput(100, output.to_script())

    # Test even sized transaction fee is proportional.
    tx = Tx(2, [ tx_input ], [ tx_output ], 0)
    assert tx.size() == 118
    assert _calculate_transaction_fee(tx) == 59

    # Test odd sized transaction fee is rounded up.
    tx_input = TxInput(os.urandom(32), 0, Script() << os.urandom(33), 10)
    tx.inputs[0] = tx_input
    assert tx.size() == 119
    assert _calculate_transaction_fee(tx) == 60


def test__sign_contract_transaction_input() -> None:
    incoming_p2pk = P2PK_Output(PUBLIC_KEY_1, Bitcoin)

    fake_prev_hash = os.urandom(32)
    outgoing_input = TxInput(fake_prev_hash, 0, Script(), 0xFFFFFFFF)
    outgoing_p2pk = P2PK_Output(PUBLIC_KEY_2, Bitcoin)
    outgoing_output = TxOutput(900, outgoing_p2pk.to_script())

    spending_tx = Tx(2, [outgoing_input], [outgoing_output], 0)
    signature_bytes = _sign_contract_transaction_input(spending_tx, incoming_p2pk.to_script_bytes(),
        1000, PRIVATE_KEY_1)[:-1]
    signature_hash = spending_tx.signature_hash(0, 1000,
        incoming_p2pk.to_script_bytes(), SigHash(SigHash.ALL | SigHash.FORKID))
    assert PUBLIC_KEY_1.verify_der_signature(signature_bytes, signature_hash, None)



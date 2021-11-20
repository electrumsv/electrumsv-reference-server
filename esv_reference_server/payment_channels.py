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

import math
import struct
from typing import cast, Tuple, Optional

from bitcoinx import Bitcoin, classify_output_script, double_sha256, InterpreterError, Ops, \
    P2MultiSig_Output, pack_byte, PrivateKey, PublicKey, Script, SigHash, Signature, \
    TruncatedScriptError, Tx, TxOutput

from .blockchain import verify_utxo_spend_async
from .constants import ChannelState, MINIMUM_CHANNEL_PAYMENT_VALUE, MINIMUM_FUNDING_VALUE, \
    SAFE_DUST_VALUE
from .keys import generate_payment_private_key, generate_payment_public_key, ServerKeys
from .sqlite_db import AccountMetadata, ChannelRow


# The minimum refund period (with a 30 second margin for the client to deliver it).
IDEAL_LOCKTIME_SECONDS = 60 * 60 * 24
MINIMUM_REFUND_SECONDS = IDEAL_LOCKTIME_SECONDS - 20
MAXIMUM_REFUND_SECONDS = IDEAL_LOCKTIME_SECONDS + 20


class PaymentChannelError(Exception):
    pass

class InvalidTransactionError(PaymentChannelError):
    pass

class InvalidRefundInputScriptError(PaymentChannelError):
    pass

class BrokenChannelError(PaymentChannelError):
    pass

class InvalidRefundValueError(BrokenChannelError):
    pass


# TODO(unittest) Variations of the multisig script with OP_RETURN and other data.
# TODO(unittest) Different thresholds and numbers of public keys.
def process_funding_script(script_bytes: bytes, server_payment_key_bytes: bytes) \
        -> Optional[P2MultiSig_Output]:
    basic_script = Script(script_bytes)
    script = classify_output_script(basic_script, Bitcoin)
    # The funding script has to be a bare multi-signature script.
    if not isinstance(script, P2MultiSig_Output):
        return None
    # The funding script has to be a 2 of 2 multi-signature script.
    if script.threshold != 2 or len(script.public_keys) != 2:
        return None
    # The funding script has to also pay to the payment key the server gave the client.
    if not any(pk.to_bytes() == server_payment_key_bytes for pk in script.public_keys):
        return None
    return script


def process_refund_contract_transaction(contract_transaction_bytes: bytes, delivery_time: int,
        funding_value: int, funding_output_script: P2MultiSig_Output, server_keys: ServerKeys,
        account_metadata: AccountMetadata, channel_row: ChannelRow) -> Tuple[bytes, bytes]:
    """
    The way a payment channel is set up, is by the client first getting the server to sign a
    version of the contract transaction that fully refunds the coins that the client is
    putting into the funding transaction.

    Raises:
    - InvalidTransactionError
    """
    assert channel_row.channel_state == ChannelState.PAYMENT_KEY_DISPENSED, "Invalid channel state"
    assert channel_row.payment_key_bytes is not None, "Missing 'payment_key_bytes' state"

    try:
        contract_transaction = Tx.from_bytes(contract_transaction_bytes)
    except struct.error:
        raise InvalidTransactionError("Contract transaction is corrupt")

    # The refund transaction should be spending the funding output that is locked in a
    # multi-signature contract between client and server. There is no reason for the refund
    # transaction to be spending anything else.
    if len(contract_transaction.inputs) != 1:
        raise InvalidTransactionError("Only the funding input should be present")

    tx_input = contract_transaction.inputs[0]
    # The refund transaction is the payment channel. It's sequence number will be incremented
    # in every payment update by the client. We expect it to start at 0 for the initial refund
    # transaction which does the full refund to the client.
    if tx_input.sequence != 0:
        raise InvalidTransactionError("The initial funding input nSequence value should be 0")

    # The refund transaction is for the client to close the payment channel and reclaim their
    # funds if the server is non-responsive. The life of the channel is limited to this time, and
    # it is expected that the server will close the channel and claim any funds they have been
    # paid before this channel expiry time is reached.
    lock_time_seconds = contract_transaction.locktime - delivery_time
    if lock_time_seconds < MINIMUM_REFUND_SECONDS or lock_time_seconds > MAXIMUM_REFUND_SECONDS:
        raise InvalidTransactionError(f"Locktime must be around {IDEAL_LOCKTIME_SECONDS} seconds")

    # It is expected that the client have locked the refund input to the refund output. This
    # means that there will be one output to match the input.
    if len(contract_transaction.outputs) != 1:
        raise InvalidTransactionError("Only one refund output should be present")

    # The staked contract funds by the client must be at least this minimum funding value.
    if funding_value < MINIMUM_FUNDING_VALUE:
        raise InvalidTransactionError(
            f"Channel funding value {funding_value} < {MINIMUM_FUNDING_VALUE}")

    # Verify that the funding value they gave us covers the refund value. We have no idea what
    # fee rate the client is paying, so we assume they can legitimately be paying no fee and
    # we do not impose any restrictions.
    if contract_transaction.outputs[0].value > funding_value:
        raise InvalidTransactionError("Refunded value higher than funded value")

    # This is the required key (and signature) ordering for client and server.
    client_key_index = 0
    server_key_index = 1

    server_payment_key = PublicKey.from_bytes(channel_row.payment_key_bytes)
    if funding_output_script.public_keys[server_key_index] != server_payment_key:
        raise InvalidTransactionError("Funding output script lacks server payment key")

    try:
        refund_script_data = list(tx_input.script_sig.ops())
    except TruncatedScriptError:
        raise InvalidRefundInputScriptError("Truncated refund input script")

    if len(refund_script_data) != 3:
        raise InvalidRefundInputScriptError("Invalid refund spend stack size")

    client_refund_signature_bytes = refund_script_data[client_key_index+1]
    if Signature.analyze_encoding(client_refund_signature_bytes) == 0:
        raise InvalidTransactionError("Invalid client refund signature")

    client_sighash = SigHash.from_sig_bytes(client_refund_signature_bytes)
    if client_sighash != SigHash(SigHash.SINGLE | SigHash.ANYONE_CAN_PAY | SigHash.FORKID):
        raise InvalidTransactionError("Invalid sighash for client refund signature")

    refund_private_key = generate_payment_private_key(server_keys.identity_private_key,
        account_metadata.public_key_bytes, channel_row.payment_key_index)
    server_refund_signature_bytes = _sign_contract_transaction_input(contract_transaction,
        funding_output_script.to_script_bytes(), funding_value, refund_private_key)

    client_refund_payment_key_bytes = funding_output_script.public_keys[client_key_index].to_bytes()
    return client_refund_payment_key_bytes, server_refund_signature_bytes


async def process_funding_transaction_async(transaction_bytes: bytes,
        channel_row: ChannelRow) -> bytes:
    """
    Raises:
    - BrokenChannelError
    """
    assert channel_row.channel_state == ChannelState.REFUND_ESTABLISHED, "Invalid channel state"
    assert channel_row.refund_signature_bytes is not None, "Missing 'refund_signature_bytes' state"

    funding_transaction_hash = double_sha256(transaction_bytes)
    if channel_row.funding_transaction_hash != funding_transaction_hash:
        raise BrokenChannelError("Funding transaction hash does not match refund prev_hash")

    try:
        contract_transaction = Tx.from_bytes(channel_row.contract_transaction_bytes)
    except struct.error as exc:
        raise BrokenChannelError("Corrupt contract transaction") from exc

    funding_output_index = contract_transaction.inputs[0].prev_idx
    # We need to make the transaction input script the full refund script so that we can see if
    # the spend is valid.
    try:
        contract_transaction.inputs[0].script_sig = _insert_refund_signature(
            contract_transaction.inputs[0].script_sig, channel_row.refund_signature_bytes)
    except InvalidRefundInputScriptError as exc:
        raise BrokenChannelError(exc.args[0]) from exc

    try:
        funding_transaction = Tx.from_bytes(transaction_bytes)
    except struct.error:
        raise BrokenChannelError("Funding transaction is corrupt")

    if len(funding_transaction.outputs) < funding_output_index + 1:
        raise BrokenChannelError("Spent refund prev_idx beyond funding outputs bounds")

    # The client should not be able to replace the funding transaction invalidating the contract
    # by giving us a funding transaction with non-final inputs.
    if not funding_transaction.are_inputs_final():
        raise BrokenChannelError("Funding transaction inputs must all be final")

    # The refund signature we gave factored in what they told us the value was. Verify that the
    # value matches.
    transaction_output = funding_transaction.outputs[funding_output_index]
    if transaction_output.value != channel_row.funding_value:
        raise BrokenChannelError("Funding transaction output value mismatch")

    # The refund signature we gave factored in what they told us the output script was. Verify
    # that the output script is what we expect it to be.
    client_public_key = PublicKey.from_bytes(channel_row.client_payment_key_bytes)
    server_public_key = PublicKey.from_bytes(channel_row.payment_key_bytes)
    expected_output_script = P2MultiSig_Output([ client_public_key, server_public_key ], 2)
    if transaction_output.script_pubkey.to_bytes() != expected_output_script.to_script_bytes():
        raise BrokenChannelError("Funding transaction output script mismatch")

    try:
        is_spend_valid = await verify_utxo_spend_async(contract_transaction, 0, transaction_output)
    except InterpreterError as exc:
        raise BrokenChannelError(f"Funding transaction script error '{exc.args[0]}'") from exc

    if not is_spend_valid:
        raise BrokenChannelError("Funding transaction spend invalid")

    return expected_output_script.to_script_bytes()


def _insert_refund_signature(input_script: Script, signature_bytes: bytes) -> Script:
    """
    The refund contract transaction given to us by the client only has their signature present and
    a placeholder for our signature. In order to verify it spends the funding output, we need
    to inject our signature.
    """
    try:
        script_parameters = list(input_script.ops())
    except TruncatedScriptError:
        raise InvalidRefundInputScriptError("Truncated refund input script")

    if len(script_parameters) != 3:
        raise InvalidRefundInputScriptError("Invalid refund spend stack size")

    # The public keys and signatures should be in the same order, client then server.
    client_refund_signature_bytes = script_parameters[1]
    return Script() << Ops.OP_0 << client_refund_signature_bytes << signature_bytes


async def process_contract_update_async(refund_signature_bytes: bytes, refund_value: int,
        channel_row: ChannelRow) -> int:
    """
    Client signature requirements:
    - Signed the refund input with an incremented sequence number (assumed).
    - Signed the refund output with the given `refund_value` (provided).

    Raises:
    - BrokenChannelError.
      - InvalidRefundValueError
    """
    # This would have been set when the contract was declared open.
    assert channel_row.channel_state == ChannelState.CONTRACT_OPEN
    assert channel_row.funding_output_script_bytes is not None
    assert channel_row.contract_transaction_bytes is not None
    assert channel_row.client_payment_key_bytes is not None
    assert channel_row.refund_value > 0

    contract_transaction = Tx.from_bytes(channel_row.contract_transaction_bytes)

    client_sighash = SigHash.from_sig_bytes(refund_signature_bytes)
    if client_sighash != SigHash(SigHash.SINGLE | SigHash.ANYONE_CAN_PAY | SigHash.FORKID):
        raise BrokenChannelError("Invalid client refund signature sighash")

    # We disallow the payment change if it is less than a minimum payment increase.
    if refund_value > channel_row.refund_value - MINIMUM_CHANNEL_PAYMENT_VALUE:
        print(refund_value, channel_row.refund_value - MINIMUM_CHANNEL_PAYMENT_VALUE)
        raise InvalidRefundValueError("Refund delta below minimum payment value")

    # TODO(safe-dust) We need to know that we can mine the transaction they are asking us to
    #     accept. If their refund decrease puts their refund below the dust level, then we won't
    #     be able to mine it.
    if refund_value <= SAFE_DUST_VALUE:
        raise InvalidRefundValueError(f"Refund <= {SAFE_DUST_VALUE} (safe dust value)")

    # We need to update the value of the refund output as the signature should have signed that.
    new_sequence = channel_row.refund_sequence + 1
    contract_transaction.inputs[0].sequence = new_sequence
    contract_transaction.outputs[0].value = refund_value

    # We manually check the signature against the public key so that we do not have to sign
    # the transaction ourselves, and put our signature in the input script. We know the spend
    # is definitely a fixed 2 of 2 bare multi-signature payment at this point, but if we
    # ever support more complicated variations like embedded push/drops, trailing OP_RETURN
    # payloads and more we probably need to have some way of dealing with that.
    client_public_key = PublicKey.from_bytes(channel_row.client_payment_key_bytes)
    der_signature_bytes, sighash = Signature.split_and_normalize(refund_signature_bytes)
    message_hash_bytes = contract_transaction.signature_hash(0, channel_row.funding_value,
        channel_row.funding_output_script_bytes, sighash)
    if not client_public_key.verify_der_signature(der_signature_bytes, message_hash_bytes,
            hasher=None):
        raise BrokenChannelError(f"Funding transaction signature invalid")

    return new_sequence


async def process_contract_close_async(client_refund_signature_bytes: bytes, refund_value: int,
        server_keys: ServerKeys, account_metadata: AccountMetadata,
        channel_row: ChannelRow) -> bytes:
    """
    Client signature requirements:
    - Signed the refund input with final sequence number 0xFFFFFFFF (assumed).
    - Signed the refund output with the given `refund_value` (provided).

    This function does not raise any exceptions.
    """
    assert channel_row.channel_state == ChannelState.CONTRACT_OPEN
    assert channel_row.contract_transaction_bytes is not None
    assert channel_row.funding_output_script_bytes is not None
    assert channel_row.refund_signature_bytes is not None

    # We should not allow the client to close the channel claiming a refund value that includes
    # the spent amount of their prepaid balance. But we should allow them to claim the unspent
    # portion.
    unspent_balance = channel_row.prepaid_balance_value - channel_row.spent_balance_value
    assert unspent_balance >= 0
    if refund_value > channel_row.refund_value + unspent_balance:
        # If they ask us for part of the spent balance, we assume it is malicious and take it all.
        # TODO(unittest) Verify that the persisted values for these are correct.
        refund_value = channel_row.refund_value
        client_refund_signature_bytes = channel_row.refund_signature_bytes

    # At this point we should know this transaction is valid and won't raise an exception.
    contract_transaction = Tx.from_bytes(channel_row.contract_transaction_bytes)
    # Update the parts that are factor into the both the client and server signing.
    contract_transaction.inputs[0].sequence = 0xFFFFFFFF
    contract_transaction.outputs[0].value = refund_value

    # Add any extra outputs here.
    # Add an output to take our payment, we do not set a value yet as we need to work out the fee.
    contract_payment_public_key = generate_payment_public_key(server_keys.identity_public_key,
        account_metadata.public_key_bytes, channel_row.payment_key_index, b"contract-payment")
    contract_payment_output = TxOutput(0, contract_payment_public_key.P2PKH_script())
    contract_transaction.outputs.append(contract_payment_output)

    # Add any extra inputs here. We need to do this before we sign the refund input as we sign
    # that as SIGHASH_ALL.
    pass

    # The transaction structure and size is fixed at this point. This allows us to work out the
    # fee and we can factor that into the values of any outputs we need to set.
    fee_value = _calculate_transaction_fee(contract_transaction)
    contract_payment_output.value = channel_row.funding_value - refund_value - fee_value

    # Verify that our transaction spends and receipts balance.
    # NOTE: If we added inputs we will need to add code to factor that in.
    assert sum(o.value for o in contract_transaction.outputs) + fee_value == \
        channel_row.funding_value, "This should balance"

    # At this point we want to know that the transaction inputs and outputs are ready for the
    # server to sign any spends, starting with the refund input.
    refund_private_key = generate_payment_private_key(server_keys.identity_private_key,
        account_metadata.public_key_bytes, channel_row.payment_key_index)
    server_refund_signature_bytes = _sign_contract_transaction_input(contract_transaction,
        channel_row.funding_output_script_bytes, channel_row.funding_value, refund_private_key)
    contract_transaction.inputs[0].script_sig = Script() << Ops.OP_0 \
        << client_refund_signature_bytes << server_refund_signature_bytes

    # If we added any other inputs, we should sign them here.
    pass

    return contract_transaction.to_bytes()


def _sign_contract_transaction_input(contract_transaction: Tx, funding_output_script_bytes: bytes,
        funding_value: int, private_key: PrivateKey, sig_hash: Optional[SigHash]=None) -> bytes:
    if sig_hash is None:
        sig_hash = SigHash(SigHash.ALL | SigHash.FORKID)
    # At this point we want to know that the signable parts of the transaction are complete and
    # we can calculate and inject the signature of those.
    signature_hash = contract_transaction.signature_hash(0, funding_value,
        funding_output_script_bytes, sig_hash)
    signature_bytes = private_key.sign(signature_hash, None)
    return signature_bytes + pack_byte(sig_hash)


# NOTE: Our initial choice to calculate the transaction fee is forcing rounded up 0.5 sats/byte.
def _calculate_transaction_fee(transaction: Tx) -> int:
    return math.ceil(transaction.size() * 0.5)

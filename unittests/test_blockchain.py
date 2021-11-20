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

from bitcoinx import Bitcoin, Ops, P2MultiSig_Output, P2PK_Output, PrivateKey, Script, Tx, \
    TxInput, TxOutput

from esv_reference_server.blockchain import verify_utxo_spend
from esv_reference_server.payment_channels import _sign_contract_transaction_input


PRIVATE_KEY_1 = PrivateKey.from_hex(
    "720f1987db69efa562b3dabd78e51f19bd8da76c70ad839b72b939f4071b144b")
PUBLIC_KEY_1 = PRIVATE_KEY_1.public_key

PRIVATE_KEY_2 = PrivateKey.from_hex(
    "8d776373012ed183b5d45dc1e543637a8c7e075de964826fd1f85ebbc6759b58")
PUBLIC_KEY_2 = PRIVATE_KEY_2.public_key

PRIVATE_KEY_3 = PrivateKey.from_hex(
    "efd70663ba73fbcd3926b683538304febb730d0be06741fa45d058bab8dd4906")
PUBLIC_KEY_3 = PRIVATE_KEY_3.public_key


def test_verify_utxo_spend_p2pk() -> None:
    incoming_p2pk = P2PK_Output(PUBLIC_KEY_1, Bitcoin)
    incoming_output = TxOutput(1000, incoming_p2pk.to_script())

    fake_prev_hash = os.urandom(32)
    outgoing_input = TxInput(fake_prev_hash, 0, Script(), 0xFFFFFFFF)
    outgoing_p2pk = P2PK_Output(PUBLIC_KEY_2, Bitcoin)
    outgoing_output = TxOutput(900, outgoing_p2pk.to_script())

    spending_tx = Tx(2, [outgoing_input], [outgoing_output], 0)
    signature_bytes = _sign_contract_transaction_input(spending_tx, incoming_p2pk.to_script_bytes(),
        1000, PRIVATE_KEY_1)
    outgoing_input.script_sig = Script() << signature_bytes

    assert verify_utxo_spend(spending_tx, 0, incoming_output)


def test_verify_utxo_spend_p2ms() -> None:
    incoming_p2ms = P2MultiSig_Output([ PUBLIC_KEY_1, PUBLIC_KEY_2 ], 2)
    incoming_output = TxOutput(1000, incoming_p2ms.to_script())

    fake_prev_hash = os.urandom(32)
    outgoing_input = TxInput(fake_prev_hash, 0, Script(), 0xFFFFFFFF)
    outgoing_p2pk = P2PK_Output(PUBLIC_KEY_3, Bitcoin)
    outgoing_output = TxOutput(900, outgoing_p2pk.to_script())

    spending_tx = Tx(2, [outgoing_input], [outgoing_output], 0)
    signature_bytes_1 = _sign_contract_transaction_input(spending_tx,
        incoming_p2ms.to_script_bytes(), 1000, PRIVATE_KEY_1)
    signature_bytes_2 = _sign_contract_transaction_input(spending_tx,
        incoming_p2ms.to_script_bytes(), 1000, PRIVATE_KEY_2)
    outgoing_input.script_sig = Script() << Ops.OP_0 << signature_bytes_1 << signature_bytes_2

    assert verify_utxo_spend(spending_tx, 0, incoming_output)

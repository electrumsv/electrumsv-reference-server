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

from bitcoinx import InterpreterLimits, MinerPolicy, Tx, TxInputContext, TxOutput


def verify_utxo_spend(transaction: Tx, input_index: int, utxo: TxOutput) -> bool:
    # We know the script we are executing so rather than trying to guess what miners actually
    # support, we go with the restrictive policy from the bitcoinx unit tests.
    is_genesis_enabled = True
    is_transaction_in_block = False
    is_utxo_after_genesis = True
    miner_policy = MinerPolicy(100_000, 64, 20_000, 1_000, 16)
    verification_limits = InterpreterLimits(miner_policy, is_genesis_enabled,
        is_transaction_in_block)
    context = TxInputContext(transaction, input_index, utxo, is_utxo_after_genesis)
    return context.verify_input(verification_limits)


async def verify_utxo_spend_async(transaction: Tx, input_index: int, utxo: TxOutput) -> bool:
    # TODO(temporary-prototype-choice) Should use a worker thread with timeout if it takes too long.
    return verify_utxo_spend(transaction, input_index, utxo)


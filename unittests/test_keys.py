# Open BSV License version 4
#
# Copyright (c) 2021 Bitcoin Association for BSV ("Bitcoin Association")
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
#
# 2 - The Software, and any software that is derived from the Software or parts thereof,
# can only be used on the Bitcoin SV blockchains. The Bitcoin SV blockchains are defined,
# for purposes of this license, as the Bitcoin blockchain containing block height #556767
# with the hash "000000000000000001d956714215d96ffc00e0afda4cd0a96c96f8d802b1662b" and
# that contains the longest persistent chain of blocks accepted by this Software and which
# are valid under the rules set forth in the Bitcoin white paper (S. Nakamoto, Bitcoin: A
# Peer-to-Peer Electronic Cash System, posted online October 2008) and the latest version
# of this Software available in this repository or another repository designated by Bitcoin
# Association, as well as the test blockchains that contain the longest persistent chains
# of blocks accepted by this Software and which are valid under the rules set forth in the
# Bitcoin whitepaper (S. Nakamoto, Bitcoin: A Peer-to-Peer Electronic Cash System, posted
# online October 2008) and the latest version of this Software available in this repository,
# or another repository designated by Bitcoin Association
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


from datetime import datetime
import os

from bitcoinx import PrivateKey

from esv_reference_server.keys import VerifiableKeyDataDict, verify_key_data


CLIENT_IDENTITY_PRIVATE_KEY_HEX = "d468816bc0f78465d4833426c280166c3810ecc9c0350c5232b0c417687fbde6"
CLIENT_IDENTITY_PRIVATE_KEY = PrivateKey.from_hex(CLIENT_IDENTITY_PRIVATE_KEY_HEX)


def _generate_client_key_data() -> VerifiableKeyDataDict:
    iso_date_text = datetime.utcnow().isoformat()
    message_bytes = b"http://server/api/account/metadata" + iso_date_text.encode()
    signature_bytes = CLIENT_IDENTITY_PRIVATE_KEY.sign_message(message_bytes)
    return {
        "public_key_hex": CLIENT_IDENTITY_PRIVATE_KEY.public_key.to_hex(),
        "message_hex": message_bytes.hex(),
        "signature_hex": signature_bytes.hex()
    }



def test_verify_key_data_correct() -> None:
    # Check that the correct key data verifies correctly.
    key_data = _generate_client_key_data()
    assert verify_key_data(key_data)

def test_verify_key_data_incorrect_signature() -> None:
    # Check that the correct signature is required for the verifiable key data to verify.
    key_data = _generate_client_key_data()
    other_private_key = PrivateKey.from_random()
    other_signature_bytes = other_private_key.sign_message(bytes.fromhex(key_data["message_hex"]))
    key_data["signature_hex"] = other_signature_bytes.hex()
    assert not verify_key_data(key_data)

def test_verify_key_data_incorrect_message() -> None:
    # Check that the correct message is required for the verifiable key data to verify.
    key_data = _generate_client_key_data()
    key_data["message_hex"] = os.urandom(32).hex()
    assert not verify_key_data(key_data)


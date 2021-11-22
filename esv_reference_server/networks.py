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


from __future__ import annotations
from enum import IntEnum
import json
import random
from typing import cast, Dict, List, Literal, Optional, TypedDict, Union

import aiohttp
from bitcoinx import PublicKey

from .constants import Network


class NetworkServer(TypedDict):
    name: str
    url: str
    public_key: Optional[PublicKey]


class JSONEnvelope(TypedDict):
    payload: str
    signature: Optional[str]
    publicKey: Optional[str]
    encoding: str
    mimetype: str


class MAPIBroadcastConflict(TypedDict):
    txid: str # Canonical hex transaction id.
    size: int
    hex: str


# A MAPI broadcast response is packaged according to the JSON envelope BRFC.
# https://github.com/bitcoin-sv-specs/brfc-misc/tree/master/jsonenvelope
class MAPIBroadcastResponse(TypedDict):
    # https://github.com/bitcoin-sv-specs/brfc-merchantapi#2-submit-transaction
    apiVersion: str
    timestamp: str
    txid: str # Canonical hex transaction id.
    returnResult: Union[Literal["success"], Literal["failure"]]
    returnDescription: str # "" or "<error message>"
    minerId: str
    currentHighestBlockHash: str
    currentHighestBlockHeight: int
    txSecondMempoolExpiry: int
    conflictedWith: List[MAPIBroadcastConflict]


# TODO(get-coinbases) There is no way to get coinbase transactions with each new block so
#   that we have the payload data like MAPI URL and miner id/public key. So hard-coded.
MAPI_ENDPOINTS: Dict[Network, List[NetworkServer]] = {
    Network.REGTEST: [
        {
            "name": "ElectrumSV SDK",
            "url":  "http://127.0.0.1:45111",
            "public_key": None
        }
    ],
    Network.MAINNET: [
        {
            "name": "TAAL",
            "url": "https://merchantapi.taal.com",
            "public_key": PublicKey.from_hex(
                "03e92d3e5c3f7bd945dfbf48e7a99393b1bfb3f11f380ae30d286e7ff2aec5a270")
        }
    ]
}


class NetworkError(Exception):
    pass

class NoAvailableServerError(NetworkError):
    pass

class BroadcastFailureError(NetworkError):
    pass

class MAPIBroadcastFailureError(BroadcastFailureError):
    pass

class InvalidJSONEnvelopeError(NetworkError):
    pass


def validate_json_envelope(server_data: NetworkServer, json_response: JSONEnvelope) -> None:
    """
    It is not necessary for a fee quote to include a signature, but if there is one we check
    it. What does it mean if there isn't one? No idea, but at this time there is no expectation
    there will be one.

    Raises a `InvalidJSONEnvelopeError` to indicate that the signature is invalid.
    """
    if server_data["public_key"] is None:
        return

    message_bytes = json_response["payload"].encode()
    if json_response["signature"] is not None and json_response["publicKey"] is not None:
        signature_bytes = bytes.fromhex(json_response["signature"])
        public_key = PublicKey.from_hex(json_response["publicKey"])
        if server_data["public_key"] != public_key:
            raise InvalidJSONEnvelopeError("MAPI public key does not match local version")
        if not public_key.verify_der_signature(signature_bytes, message_bytes):
            raise InvalidJSONEnvelopeError("MAPI signature invalid")


async def mapi_broadcast_transaction(network: Network, transaction_bytes: bytes) -> str:
    """
    Broadcast the transaction through a MAPI endpoint for the given network.

    On success, returns the text JSON envelope returned by the MAPI API.
    On error, raises these exceptions:
    - aiohttp.ClientError
    - NetworkError
      - NoAvailableServerError
      - BroadcastFailureError
      - MAPIBroadcastFailureError
    """
    # TODO(get-coinbases) There is no way to get coinbase transactions with each new block so
    #   that we have the payload data like MAPI URL and miner id/public key. So hard-coded.
    mapi_servers = MAPI_ENDPOINTS.get(network, [])
    if len(mapi_servers) == 0:
        raise NoAvailableServerError

    server_data = random.choice(mapi_servers)
    broadcast_url = server_data["url"] +"/mapi/tx"
    async with aiohttp.ClientSession() as session:
        async with session.post(broadcast_url, data=transaction_bytes) as response:
            if response.status != 200:
                raise BroadcastFailureError(response.reason)

            envelope_text = await response.text()
            envelope = cast(JSONEnvelope, json.loads(envelope_text))
            validate_json_envelope(server_data, envelope)

    response = cast(MAPIBroadcastResponse, json.loads(envelope["payload"]))
    if response["returnResult"] == "failure":
        raise MAPIBroadcastFailureError(response["returnDescription"])

    return envelope_text

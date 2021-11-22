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
import asyncio
from datetime import datetime
import json
import logging
import time
from typing import cast, Optional, Tuple, TypedDict

import aiohttp
from aiohttp import web
from bitcoinx import Ops, P2MultiSig_Output, pack_byte, PrivateKey, PublicKey, Script, SigHash, \
    Signature, Tx, TxInput, TxOutput


logger = logging.getLogger("client")

# These are the default host and port from the main `esv_reference_server` package.
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 47124

# This is the endpoint and pricing definition endpoint.
SERVER_API_URL = f"http://{SERVER_HOST}:{SERVER_PORT}/api/v1/endpoints"

MAPI_PORT = 45111

# The "endpoint" entry if the account endpoint is supported.
ACCOUNT_API_NAME = "bsvapi.account"
ACCOUNT_API_VERSION = 1

# The minimum refund period (with a 30 second margin for the client to deliver it).
IDEAL_LOCKTIME_SECONDS = 60 * 60 * 24
MINIMUM_REFUND_SECONDS = IDEAL_LOCKTIME_SECONDS - 20
MAXIMUM_REFUND_SECONDS = IDEAL_LOCKTIME_SECONDS + 20

CLIENT_IDENTITY_PRIVATE_KEY_HEX = "810363a6ec9c41b9f86dda905ef19ecc94cb0635a229432c5bd7c75b3fa78a29"
CLIENT_IDENTITY_PRIVATE_KEY = PrivateKey.from_hex(CLIENT_IDENTITY_PRIVATE_KEY_HEX)
CLIENT_IDENTITY_PUBLIC_KEY = CLIENT_IDENTITY_PRIVATE_KEY.public_key

CLIENT_PAYMENT_PRIVATE_KEY1_HEX = "8b4c8550287e4dc03d5858a3fd3b820468c9068706ef88e7acfaac43a96f7d79"
CLIENT_PAYMENT_PRIVATE_KEY1 = PrivateKey.from_hex(CLIENT_PAYMENT_PRIVATE_KEY1_HEX)
CLIENT_PAYMENT_PUBLIC_KEY1 = CLIENT_PAYMENT_PRIVATE_KEY1.public_key

CLIENT_PAYMENT_PRIVATE_KEY2_HEX = "4fcbd7cc531280d16817900f1d264975a82f935f18a62841539b7b34d2c2cfe8"
CLIENT_PAYMENT_PRIVATE_KEY2 = PrivateKey.from_hex(CLIENT_PAYMENT_PRIVATE_KEY2_HEX)
CLIENT_PAYMENT_PUBLIC_KEY2 = CLIENT_PAYMENT_PRIVATE_KEY2.public_key

CLIENT_CONTRACT_SIGHASH = SigHash(SigHash.SINGLE | SigHash.ANYONE_CAN_PAY | SigHash.FORKID)

CONTRACT_FUNDING_VALUE = 300000


class EndpointDeclaration(TypedDict):
    apiType: str
    apiVersion: int
    baseUrl: str


class VerifiableKeyData(TypedDict):
    public_key_hex: str
    signature_hex: str
    message_hex: str


async def resolve_account_endpoint_url_async() -> Optional[str]:
    """
    Use the endpoint URL to resolve if the server supports the account endpoint, and
    to work out the top-level account API URL.
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(SERVER_API_URL) as response:
                if response.status != 200:
                    logger.error("resolver response had unexpected status %d (%s)",
                        response.status, response.reason)
                    return None

                endpoints_data = await response.json()

            assert SERVER_API_URL.startswith(endpoints_data["baseUrl"] +"/")

            endpoint_data: EndpointDeclaration
            for endpoint_data in endpoints_data["endpoints"]:
                if endpoint_data["apiType"] == ACCOUNT_API_NAME and \
                        endpoint_data["apiVersion"] == ACCOUNT_API_VERSION:
                    break
            else:
                logger.error("resolver unable to locate a '%s' endpoint", ACCOUNT_API_NAME)
                return None

            account_api_url = f"http://{SERVER_HOST}:{SERVER_PORT}{endpoint_data['baseUrl']}"
            logger.info("resolver located '%s' url at '%s'", ACCOUNT_API_NAME, account_api_url)
            return account_api_url
    except aiohttp.ClientConnectorError:
        logger.error("resolver unable to connect to server at %s", SERVER_API_URL)
        return None


async def obtain_server_payment_key_async(account_api_url: str) -> Optional[Tuple[PublicKey, str]]:
    obtain_server_key_url = account_api_url +"/key"

    try:
        # Test that unknown authorization headers get 400 (bad request) response.
        headers = { "Authorization": "random stuff" }
        async with aiohttp.ClientSession() as session:
            async with session.post(obtain_server_key_url, headers=headers) as response:
                if response.status != 400:
                    logger.error("unexpected status in payment key endpoint response (random) "
                        "%d (%s)", response.status, response.reason)
                    return None

        # Test that unrecognised bearer tokens get a 401 (unauthorized) response.
        headers = { "Authorization": "Bearer random stuff" }
        async with aiohttp.ClientSession() as session:
            async with session.post(obtain_server_key_url, headers=headers) as response:
                if response.status != 401:
                    logger.error("unexpected status in payment key endpoint response (bearer) "
                        "%d (%s)", response.status, response.reason)
                    return None

        # Test that the "BSV key data" gets a payment key response.
        timestamp_text = datetime.utcnow().isoformat()
        message_text = f"{obtain_server_key_url} {timestamp_text}"
        signature_bytes = CLIENT_IDENTITY_PRIVATE_KEY.sign_message(message_text.encode())

        key_data: VerifiableKeyData = {
            "public_key_hex": CLIENT_IDENTITY_PUBLIC_KEY.to_hex(),
            "signature_hex": signature_bytes.hex(),
            "message_hex": message_text.encode().hex(),
        }
        payment_key_bytes: Optional[bytes] = None
        api_key: Optional[str] = None
        async with aiohttp.ClientSession() as session:
            async with session.post(obtain_server_key_url, json=key_data) as response:
                if response.status != 200:
                    logger.error("unexpected status in payment key endpoint response (vkd) %d (%s)",
                        response.status, response.reason)
                    return None

                reader = aiohttp.MultipartReader.from_response(response)
                while True:
                    part = cast(aiohttp.BodyPartReader, await reader.next())
                    if part is None:
                        break
                    elif part.name == "key":
                        payment_key_bytes = bytes(await part.read(decode=True))
                    elif part.name == "api-key":
                        api_key = await part.text()
    except aiohttp.ClientConnectorError:
        logger.error("resolver unable to connect to server at %s", SERVER_API_URL)
        return None

    if payment_key_bytes is None:
        logger.error("payment key not obtained")
        return None

    if api_key is None:
        logger.error("API key not obtained")
        return None

    try:
        payment_key = PublicKey.from_bytes(payment_key_bytes)
    except ValueError:
        logger.error("invalid payment key obtained")
        return None

    return payment_key, api_key


def create_funding_transaction(server_payment_key) -> Tx:
    p2ms_output = P2MultiSig_Output([ CLIENT_PAYMENT_PUBLIC_KEY1, server_payment_key ], 2)

    imaginary_transaction_hash = bytes.fromhex(
        "3a0209bf13be86d806da43436b13f2c0c957df78691802bb59a8cfc5809a5f98")
    funding_input = TxInput(imaginary_transaction_hash, 0, Script(), 0xFFFFFFFF)
    funding_output = TxOutput(CONTRACT_FUNDING_VALUE, p2ms_output.to_script())
    return Tx(2, [funding_input], [funding_output], 0)


def create_refund_transaction(funding_transaction: Tx) -> Tx:
    locktime = int(time.time() + IDEAL_LOCKTIME_SECONDS)
    # This is the first version of the contract transaction, so sequence=0.
    refund_input = TxInput(funding_transaction.hash(), 0, Script(), 0)
    refund_output = TxOutput(CONTRACT_FUNDING_VALUE, CLIENT_PAYMENT_PUBLIC_KEY1.P2PKH_script())
    # The spend of the refund input is restricted until after a day has passed.
    refund_transaction = Tx(2, [refund_input], [refund_output], locktime)

    signature_hash = refund_transaction.signature_hash(0, funding_transaction.outputs[0].value,
        funding_transaction.outputs[0].script_pubkey, CLIENT_CONTRACT_SIGHASH)
    refund_signature_bytes = CLIENT_PAYMENT_PRIVATE_KEY1.sign(signature_hash, None)
    refund_signature_bytes += pack_byte(CLIENT_CONTRACT_SIGHASH)
    refund_transaction.inputs[0].script_sig = \
        Script() << Ops.OP_0 << refund_signature_bytes << bytes(32)

    return refund_transaction


async def send_refund_transaction(account_api_url: str, api_key: str, funding_transaction: Tx,
        refund_transaction: Tx) -> Optional[bytes]:
    send_refund_transaction_url = account_api_url +"/channel"

    funding_output_script = funding_transaction.outputs[0].script_pubkey
    funding_value = funding_transaction.outputs[0].value

    headers = { "Authorization": f"Bearer {api_key}" }
    mpwriter = aiohttp.MultipartWriter()
    part = mpwriter.append(funding_output_script.to_bytes())
    part.set_content_disposition('inline', name="script")

    part = mpwriter.append(refund_transaction.to_bytes())
    part.set_content_disposition('inline', name="transaction")

    async with aiohttp.ClientSession() as session:
        async with session.post(send_refund_transaction_url, headers=headers,
                data=mpwriter, params={ "funding_value": funding_value }) as response:
            if response.status != 200:
                logger.error("unexpected status in refund endpoint response (bearer) %d (%s)",
                    response.status, response.reason)
                return None

            return await response.read()


def insert_server_signature(funding_transaction: Tx, refund_transaction: Tx,
        server_payment_key: PublicKey, server_signature_bytes: bytes) -> bool:
    script_parts = list(refund_transaction.inputs[0].script_sig.ops())
    refund_transaction.inputs[0].script_sig = Script() << Ops.OP_0 << script_parts[1] \
        << server_signature_bytes

    der_signature_bytes, sighash = Signature.split_and_normalize(server_signature_bytes)
    message_hash_bytes = refund_transaction.signature_hash(0,
        funding_transaction.outputs[0].value,
        funding_transaction.outputs[0].script_pubkey.to_bytes(), sighash)
    if server_payment_key.verify_der_signature(der_signature_bytes, message_hash_bytes, None):
        logger.info("server has signed our initial contract refund version")
        return True
    logger.error("invalid server refund signature")
    return False


async def send_funding_transaction(account_api_url: str, api_key: str,
        funding_transaction: Tx) -> bool:
    send_refund_transaction_url = account_api_url +"/funding"

    headers = { "Authorization": f"Bearer {api_key}" }
    mpwriter = aiohttp.MultipartWriter()
    part = mpwriter.append(funding_transaction.to_bytes())
    part.set_content_disposition('inline', name="transaction")

    async with aiohttp.ClientSession() as session:
        async with session.post(send_refund_transaction_url, headers=headers,
                data=mpwriter) as response:
            if response.status != 200:
                logger.error("unexpected status in funding endpoint response (bearer) %d (%s)",
                    response.status, response.reason)
                return False
            logger.info("funding transaction given to server")
            return True


async def send_contract_payment(account_api_url: str, api_key: str, funding_transaction: Tx,
        refund_transaction: Tx, new_refund_value: int) -> Optional[Tx]:
    send_refund_transaction_url = account_api_url +"/channel"

    contract_transaction = Tx.from_bytes(refund_transaction.to_bytes())
    contract_transaction.inputs[0].sequence += 1
    contract_transaction.outputs[0].value = new_refund_value

    signature_hash = contract_transaction.signature_hash(0, funding_transaction.outputs[0].value,
        funding_transaction.outputs[0].script_pubkey, CLIENT_CONTRACT_SIGHASH)
    new_refund_signature_bytes = CLIENT_PAYMENT_PRIVATE_KEY1.sign(signature_hash, None)
    new_refund_signature_bytes += pack_byte(CLIENT_CONTRACT_SIGHASH)

    headers = { "Authorization": f"Bearer {api_key}" }
    mpwriter = aiohttp.MultipartWriter()
    part = mpwriter.append(new_refund_signature_bytes)
    part.set_content_disposition('inline', name="signature")

    async with aiohttp.ClientSession() as session:
        async with session.put(send_refund_transaction_url, headers=headers,
                data=mpwriter, params={ "refund_value": new_refund_value }) as response:
            if response.status != 200:
                logger.error("unexpected status in refund endpoint response (bearer) %d (%s)",
                    response.status, response.reason)
                return None
            logging.info("contract payment accepted")
            return contract_transaction


async def _run_client() -> None:
    account_api_url = await resolve_account_endpoint_url_async()
    if account_api_url is None:
        return

    key_result = await obtain_server_payment_key_async(account_api_url)
    if key_result is None:
        return
    server_payment_key, api_key = key_result

    funding_transaction = create_funding_transaction(server_payment_key)
    refund_transaction = create_refund_transaction(funding_transaction)

    server_signature_bytes = await send_refund_transaction(account_api_url, api_key,
        funding_transaction, refund_transaction)
    if server_signature_bytes is None:
        return

    if not insert_server_signature(funding_transaction, refund_transaction, server_payment_key,
            server_signature_bytes):
        return

    await send_funding_transaction(account_api_url, api_key, funding_transaction)

    refund_value = CONTRACT_FUNDING_VALUE - 10000
    contract_transaction = await send_contract_payment(account_api_url, api_key,
        funding_transaction, refund_transaction, refund_value)
    if contract_transaction is None:
        return

    # TODO: Server unspent balance accounting is not implemented yet. Do something with that.
    # TODO: Call a function accessible to fully registered users like ourselves now we have paid.
    #       When we made the first payment, we moved from "mid-registration" to "registered".
    #       This should allow us to call some API limited to paying users who have an unspent
    #       prepaid balance (like us).


async def run_client(event: asyncio.Event) -> None:
    try:
        await _run_client()
    finally:
        event.set()


async def run_fake_mapi_server(runner: web.AppRunner, event: asyncio.Event) -> None:
    """
    Run a fake localhost MAPI endpoint for broadcasting transactions.
    """
    site = web.TCPSite(runner, 'localhost', MAPI_PORT)
    await site.start()
    await event.wait()



async def mapi_broadcast(request: web.Request) -> web.Response:
    logger.info("received mapi broadcast of presumably the funding transaction")
    return web.json_response({
        "payload": json.dumps({ "returnResult": "success" })
    })


async def main() -> None:
    event = asyncio.Event()

    app = web.Application()
    app.add_routes([
        web.post('/mapi/tx', mapi_broadcast)
    ])

    runner = web.AppRunner(app)
    await runner.setup()
    try:
        await asyncio.gather(run_client(event), run_fake_mapi_server(runner, event))
    except KeyboardInterrupt:
        await runner.cleanup()


def run() -> None:
    logging.basicConfig(format='%(asctime)s %(levelname)-8s %(name)-24s %(message)s',
        level=logging.DEBUG, datefmt='%Y-%m-%d %H:%M:%S')

    asyncio.run(main())


if __name__ == "__main__":
    run()

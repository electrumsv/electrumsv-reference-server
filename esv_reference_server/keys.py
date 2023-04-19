import logging
import os
import sys
from typing import cast, NamedTuple, TypedDict

from bitcoinx import PrivateKey, PublicKey, sha256

from .constants import REGTEST_IDENTITY_PRIVATE_KEY, REGTEST_IDENTITY_PUBLIC_KEY


logger = logging.getLogger('keys')

# TODO(temporary-prototype-choice) Rotating server identity public/private keys based on date?
class ServerKeys(NamedTuple):
    identity_private_key: PrivateKey
    identity_public_key: PublicKey


def create_regtest_server_keys() -> ServerKeys:
    return ServerKeys(REGTEST_IDENTITY_PRIVATE_KEY, REGTEST_IDENTITY_PUBLIC_KEY)


def get_server_keys() -> ServerKeys:
    try:
        PRIVATE_KEY_HEX = os.environ['SERVER_PRIVATE_KEY']
    except KeyError:
        logger.error("'SERVER_PRIVATE_KEY' is a required environment variable")
        sys.exit(1)

    assert len(PRIVATE_KEY_HEX) == 64, "Server private key must be 32 hex bytes in length"
    PRIVATE_KEY = PrivateKey.from_hex(PRIVATE_KEY_HEX)
    IDENTITY_MESSAGE = sha256(b"identity 20211117 zzz")
    IDENTITY_PRIVATE_KEY = PRIVATE_KEY.add(IDENTITY_MESSAGE)
    IDENTITY_PUBLIC_KEY = REGTEST_IDENTITY_PRIVATE_KEY.public_key
    return ServerKeys(IDENTITY_PRIVATE_KEY, IDENTITY_PUBLIC_KEY)


class VerifiableKeyDataDict(TypedDict):
    public_key_hex: str
    signature_hex: str
    message_hex: str


def verify_key_data(key_data: VerifiableKeyDataDict) -> bool:
    """
    Raises `KeyError` if one of the expected fields is not present.
    Raises `TypeError` if an expected field is not a string (from `bytes.fromhex`).
    Raises `ValueError` if an expected field is not valid hexadecimal (from `bytes.fromhex`,
        `bitcoinx.from_hex`).
    Raises `ValueError` if the public key is invalid (from `bitcoinx.from_hex`).
    """
    assert isinstance(key_data, dict)
    public_key = PublicKey.from_hex(key_data["public_key_hex"])
    signature_bytes = bytes.fromhex(key_data["signature_hex"])
    message_bytes = bytes.fromhex(key_data["message_hex"])
    return cast(bool, public_key.verify_message(signature_bytes, message_bytes))

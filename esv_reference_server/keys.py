import struct
from typing import NamedTuple, TypedDict, cast

from bitcoinx import PrivateKey, PublicKey, sha256

from .constants import REGTEST_IDENTITY_PRIVATE_KEY, REGTEST_IDENTITY_PUBLIC_KEY


# TODO(temporary-prototype-choice) Rotating server identity public/private keys based on date?
class ServerKeys(NamedTuple):
    identity_private_key: PrivateKey
    identity_public_key: PublicKey


def create_regtest_server_keys() -> ServerKeys:
    return ServerKeys(REGTEST_IDENTITY_PRIVATE_KEY, REGTEST_IDENTITY_PUBLIC_KEY)


class VerifiableKeyData(TypedDict):
    public_key_hex: str
    signature_hex: str
    message_hex: str


def verify_key_data(key_data: VerifiableKeyData) -> bool:
    public_key = PublicKey.from_hex(key_data["public_key_hex"])
    signature_bytes = bytes.fromhex(key_data["signature_hex"])
    message_bytes = bytes.fromhex(key_data["message_hex"])
    return cast(bool, public_key.verify_message(signature_bytes, message_bytes))


def generate_payment_public_key(server_identity_public_key: PublicKey,
        client_identity_key_bytes: bytes, key_count: int, extra_message: bytes=b"") -> PublicKey:
    # TODO(temporary-prototype-choice) This is very simplistic. In the real world we would have
    #     some kind of derivation where the client couldn't enumerate the addresses we have given
    #     out.
    message = client_identity_key_bytes + struct.pack("<Q", key_count) + extra_message
    message_hash = sha256(message)
    payment_key = server_identity_public_key.add(message_hash)
    return payment_key


def generate_payment_private_key(server_identity_private_key: PrivateKey,
        client_identity_key_bytes: bytes, key_count: int, extra_message: bytes=b"") -> PrivateKey:
    # TODO(temporary-prototype-choice) This is very simplistic. In the real world we would have
    #     some kind of derivation where the client couldn't enumerate the addresses we have given
    #     out.
    message = client_identity_key_bytes + struct.pack("<Q", key_count) + extra_message
    message_hash = sha256(message)
    payment_key = server_identity_private_key.add(message_hash)
    return payment_key

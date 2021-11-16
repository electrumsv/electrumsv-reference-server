from typing import TypedDict

from bitcoinx import PublicKey


class VerifiableKeyData(TypedDict):
    public_key_hex: str
    signature_hex: str
    message_hex: str


def verify_key_data(key_data: VerifiableKeyData) -> bool:
    public_key = PublicKey.from_hex(key_data["public_key_hex"])
    signature_bytes = bytes.fromhex(key_data["signature_hex"])
    message_bytes = bytes.fromhex(key_data["message_hex"])
    return public_key.verify_message(signature_bytes, message_bytes)


from bitcoinx import PrivateKey
from datetime import datetime
import json

from esv_reference_server.keys import VerifiableKeyDataDict

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


if __name__ == '__main__':
    print(json.dumps(_generate_client_key_data()))

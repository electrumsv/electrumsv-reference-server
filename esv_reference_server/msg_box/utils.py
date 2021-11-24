import base64
import os


def create_external_id():
    rnd_bytes = os.urandom(64)
    return base64.urlsafe_b64encode(rnd_bytes).decode('utf-8')


create_channel_api_token = create_external_id

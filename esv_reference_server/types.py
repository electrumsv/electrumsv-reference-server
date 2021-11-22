from typing import NamedTuple


class PeerChannelAccountRow(NamedTuple):
    peer_channel_account_id: int
    peer_channel_account_name: str
    peer_channel_username: str
    peer_channel_password: str
    account_id: int

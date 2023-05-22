"""
Copyright(c) 2021 Bitcoin Association.
Distributed under the Open BSV software license, see the accompanying file LICENSE
"""

from enum import IntEnum, IntFlag

from bitcoinx import PrivateKey, sha256


EXTERNAL_SERVER_HOST = "127.0.0.1"
EXTERNAL_SERVER_PORT = 47124
EXTERNAL_FQDN = "x.bitcoinx.io"
INTERNAL_SERVER_HOST = "127.0.0.1"
INTERNAL_SERVER_PORT = 47126

# These should be used for Regtest only.
REGTEST_PRIVATE_KEY_HEX = "9f9746a336ebf3748fe8e790f979075b785a4ec9ae1cbdfb9692ee024a03a3cb"
REGTEST_PRIVATE_KEY = PrivateKey.from_hex(REGTEST_PRIVATE_KEY_HEX)
REGTEST_IDENTITY_MESSAGE = sha256(b"identity 20211117 zzz")
REGTEST_IDENTITY_PRIVATE_KEY = REGTEST_PRIVATE_KEY.add(REGTEST_IDENTITY_MESSAGE)
REGTEST_IDENTITY_PUBLIC_KEY = REGTEST_IDENTITY_PRIVATE_KEY.public_key

DEFAULT_DATABASE_NAME = 'esv_reference_server.sqlite'


# Around 0.5000 NZD as of 2021-11-21
MINIMUM_FUNDING_VALUE = 210000
# Around 0.0025 NZD as of 2021-11-21
MINIMUM_CHANNEL_PAYMENT_VALUE = 1000


#### TRANSACTION MINING VALIDITY SETTINGS

# Any transaction that we will be passing to a MAPI endpoint in order to get mined, will have
# to be acceptable to them.

# We do not know what output dust value will be rejected by miners.
SAFE_DUST_VALUE = 546


class AccountFlag(IntFlag):
    NONE                                    = 0

    DISABLED_FLAGGED                        = 1 << 10

    DISABLED_MASK                           = DISABLED_FLAGGED


class Network(IntEnum):
    REGTEST = 1
    TESTNET = 2
    STN = 3
    MAINNET = 4


class AccountMessageKind(IntEnum):
    PEER_CHANNEL_MESSAGE = 1
    SPENT_OUTPUT_EVENT = 2


ACCOUNT_MESSAGE_NAMES: dict[AccountMessageKind, str] = {
    AccountMessageKind.PEER_CHANNEL_MESSAGE: "bsvapi.channels.notification",
    AccountMessageKind.SPENT_OUTPUT_EVENT: "bsvapi.output-spends.notification",
}


class IndexerPushdataRegistrationFlag(IntFlag):
    NONE                            = 0
    FINALISED                       = 1 << 0
    DELETING                        = 1 << 1


    MASK_DELETING_CLEAR             = ~DELETING
    MASK_FINALISED_CLEAR            = ~FINALISED
    MASK_FINALISED_DELETING_CLEAR   = ~(FINALISED | DELETING)


class OutboundDataFlag(IntFlag):
    NONE                                    = 0

    TIP_FILTER_NOTIFICATIONS                = 1 << 0

    DISPATCH_NO_CALLBACK                    = 1 << 18
    DISPATCH_EXCEPTION                      = 1 << 19
    DISPATCHED_SUCCESSFULLY                 = 1 << 20

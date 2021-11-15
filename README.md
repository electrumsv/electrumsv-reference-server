ElectrumSV Reference Server
===========================

    Licence: The Open BSV License
    Maintainers: Roger Taylor, AustEcon
    Project Lead: Roger Taylor
    Homepage: https://electrumsv.io/


Overview
========
This server is designed to expose virtually all of the APIs that ElectrumSV depends on
under one roof. The full set of APIs are divided into sub-groupings, each containing
one or more endpoints:

#### API Support API
- `GET /api/discovery` -  Retrieves the metadata about the supported APIs and their pricing policies.

#### Backup API (Optional - requires running Peer Channels instance)
These endpoints sit in-front of the Peer Channels store as a security layer. The user
will be required to sign a message to gain access to the encrypted messages contained
within their allocated Peer Channel.
- `POST /api/v1/backup/<public key>` - Create a backup-oriented peer channel.
- `GET /api/v1/backup/<public key>` - Locate an existing backup-oriented peer channel.

#### Header API (Optional - requires running HeaderSV instance)
- `GET /api/v1/headers?height=<start height>&count=<header count>` - Fetch <header count> headers beginning at <start height> from the currently valid blockchain. This returned as a streamed set of consecutive headers, in binary 80 byte form.
- `WEBSOCKET /api/v1/headers/websocket` - Sends the current 80 byte binary tip header followed by the 4 byte big endian blockchain height of the given block. As the service processes new blocks, it will announce the new tip. This can be used to infer reorgs and missing headers based on the hash of the previous block and the given height.

#### Peer Channel API (Optional - requires running Peer Channels instance)
- Ideally, identical to the reference API (but it's possible customisations may be required) - TBD

#### Paymail Hosting API
- TBD

## Payment Protocol
This has not been fully fleshed out but eventually each of these APIs would need
to have a way of specifying a pricing policy for soliciting payments for usage of
the service - essential for sustainability as the blockchain scales and the economic 
costs of maintaining such services starts to become a factor.

## Inclusion in the SDK
This server will be included in the [ElectrumSV SDK](https://github.com/electrumsv/headless-sdk/releases) 
which aims to provide a first-class RegTest developer experience. 
This is by providing a quick-launch toolkit for running services against a RegTest node.


## Running The ElectrumSV Reference Server
On windows:

    pip install -r requirements.txt
    py server.py

On unix:

    pip3 install -r requirements.txt
    python3 server.py

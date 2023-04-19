ElectrumSV Reference Server
===========================
Detailed API [documentation](https://electrumsv.github.io/electrumsv-reference-server/swagger/) can
be found [here](https://electrumsv.github.io/electrumsv-reference-server/swagger/)

    Licence: The Open BSV License
    Maintainers: Roger Taylor, AustEcon
    Project Lead: Roger Taylor
    Homepage: https://electrumsv.io/


Overview
========

The motivation for this project is to provide access to the APIs that ElectrumSV needs
moving into the future where things like managing peer channels and accessing useful blockchain
data is part of day to day Bitcoin usage. The APIs we need are as yet not available anywhere else.

It is envisioned that users can adapt this project and run their own server to provide some of
these APIs for their own use. Businesses can also adapt or use it as a reference for ensuring
compatibility, and host APIs for any interested users.

Note that implementations for all APIs are not provided. The blockchain data access will not be
able to be hosted by users. As block sizes increase developing and running a server to
process the mempool, new blocks and extract blockchain data of interest will become more and work.
This is something that will likely only be done by businesses that invest in both the work and
maintenance required.

What follows is a high-level overview of the different API subsections. More detailed
documentation of how to use each endpoint will be hosted on our swagger API page.

### Endpoint Discovery & Account management (Built-in)
Users of this service will need to open a micropayment channel
(or use an alternative payment modality) to make pro-rata payments
for their consumption of this service. Upon account creation, a
"Master Bearer Token" will be issued which grants access to any
of the other endpoints and trumps the access privileges of any
other Bearer Tokens (for example the ones generated for each
Peer Channel that is created).

 Endpoint                                                 | Method | Auth?  | Description
 -------------------------------------------------------- | ------ | ------ | -----------
 `/api/v1/endpoints`                                      | GET    | No     | Retrieves the metadata about the supported APIs
 `/api/v1/account`                                        | GET    | Yes    | Return account information
 `/api/v1/account/key`                                    | POST   | Special| Post keys and create an account

### Peer Channel API (Built-in)
This is a Python implementation of C#/ASP.NET Core reference implementation
 [reference implementation](https://github.com/bitcoin-sv/spvchannels-reference) &
 the [brfc specification](https://github.com/bitcoin-sv-specs/brfc-spvchannels) for it.
 The API is virtually identical except that the channel management APIs use
 the "Master Bearer Token" for authorization (see: Account management APIs above)
 rather than what the reference Peer Channels implementation does which is to use
 Basic Auth & an account_id in the url path. Beyond this slight change to the url
 paths and the authorization universally using Bearer Tokens, there is no material
 difference.

##### Channel Management APIs
All of these APIs require the "Master Bearer Token" for access (see previous: Account management).

 Endpoint                                                 | Method | Auth?  | Description
 -------------------------------------------------------- | ------ | ------ | -----------
 `/api/v1/channel/manage/list`                            | GET    | Yes    | List all Peer Channels
 `/api/v1/channel/manage/{channelid}`                     | GET    | Yes    | Get single channel details
 `/api/v1/channel/manage/{channelid}`                     | POST   | Yes    | Update single channel details
 `/api/v1/channel/manage/{channelid}`                     | DELETE | Yes    | Delete a channel
 `/api/v1/channel/manage/`                                | POST   | Yes    | Create a new Peer Channel
 `/api/v1/channel/manage/{channelid}/api-token/{tokenid}` | GET    | Yes    | Get token details
 `/api/v1/channel/manage/{channelid}/api-token/{tokenid}` | DELETE | Yes    | Revoke selected token
 `/api/v1/channel/manage/{channelid}/api-token`           | GET    | Yes    | Get a list of tokens for the selected channel
 `/api/v1/channel/manage/{channelid}/api-token`           | POST   | Yes    | Create a new token for the selected channel

##### Message Management APIs
For the message management APIs, there are two classes of Bearer token that can be used:

  - The "Master Bearer Token" - grants all access privileges to any channel
  - The standard, peer-channel, Bearer Token that was issued at the time of channel creation
    (subsequently generated tokens also fall into this category and may be for read-only access)

  Endpoint                                                 | Method | Auth?  | Description
 -------------------------------------------------------- | ------ | ------ | -----------
 `/api/v1/channel/{channelid}`                            | POST   | Yes    | Write message to channel
 `/api/v1/channel/{channelid}`                            | HEAD   | Yes    | Get max sequence number of channel
 `/api/v1/channel/{channelid}`                            | GET    | Yes    | Get messages from channel
 `/api/v1/channel/{channelid}/{sequence}`                 | POST   | Yes    | Mark messages as read or unread
 `/api/v1/channel/{channelid}/{sequence}`                 | DELETE | Yes    | Delete messages from channel
 `/api/v1/channel/{channelid}/notify`                     | GET    | Yes    | Subscribe to websocket notifications for new messages

### Header API (Optional)
These endpoints will become activated if there is a running instance of
[HeaderSV](https://github.com/bitcoin-sv/block-headers-client)
and the system administrator has set these environment variables:

    EXPOSE_HEADER_SV_APIS=1
    HEADER_SV_URL=http://localhost:33444

These environment variables will essentially cause ElectrumSV-Reference-Server to
act as a secure reverse proxy for HeaderSV APIs. The `.env` file at the
top-level of this repository is the default location for loading environment variables
at startup from file.

Endpoint                                                   | Method | Auth?  | Description
 --------------------------------------------------------- | ------ | ------ | -----------
 `/api/v1/headers/{hash}`                                  | GET    | No    | Get a single raw block header by hash
 `/api/v1/headers/by-height/?height=<height>&count=<count>`| GET    | No    | Get a batch of headers by height & count
 `/api/v1/headers/tips/websocket`                          | GET    | No     | Get chain tips
 `/api/v1/headers/tips`                                    | GET    | No     | Subscribe to websocket notifications of the new chain tip

### Indexer API (Provide your own implementation)

As mentioned above the work involved in implementing the support required to provide this API
is prohibitive and only likely to be done by businesses. The ElectrumSV project has many other
focuses and no interest whatsoever on provided an implementation that can be used anywhere other
than on a local temporary development Regtest network.

These endpoints will become activated if there is a running instance of a service that provides
the indexing APIs, which will be mirrored and authenticated by the reference server. The system
administrator must set these environment variables:

    EXPOSE_INDEXER_APIS=1
    INDEXER_URL=http://127.0.0.1:49241

Endpoint                                                   | Method | Auth?  | Description
 --------------------------------------------------------- | ------ | ------ | -----------
 `/api/v1/restoration/search`                              | POST   | Yes    | Locate pushdata usage in the fixed height restoration index.
 `/api/v1/transaction/filter`                              | GET    | Yes    | Read the currently registered pushdata hash filtering registrations.
 `/api/v1/transaction/filter`                              | POST   | Yes    | Request new pushdata hash filtering registrations.
 `/api/v1/transaction/filter:delete`                       | POST   | Yes    | Delete selected current registered pushdata hash filtering registrations.
 `/api/v1/transaction/{txid}`                              | GET    | Yes    | Get the given transaction.
 `/api/v1/merkle-proof/{txid}`                             | GET    | Yes    | Get the merkle proof for a given transaction.
 `/api/v1/output-spend`                                    | POST   | Yes    | Get the state of given UTXOs, whether in mempool or mined.
 `/api/v1/output-spend/notifications`                      | POST   | Yes    | Register the given UTXOs to notify if they are spent returning any existing state

A very simple implementation of these APIs for the Regtest network is provided in the form of
the ElectrumSV [Simple Indexer](https://github.com/electrumsv/simple-indexer/) project.
This is used for development of ElectrumSV projects and also to serve as an illustration of what
third parties need to do at a very simplistic level to develop their own implementations that
can work on networks like Testnet, Mainnet and Scaling Testnet.

## Pro-Rata Payment Protocol

*This is a work in progress*

## Inclusion in the SDK
This server will be included in the [ElectrumSV SDK](https://github.com/electrumsv/headless-sdk/releases)
which aims to provide a first-class RegTest developer experience.
This is by providing a quick-launch toolkit for running services against a RegTest node.

## Running The ElectrumSV Reference Server
On windows (requires Python 3.10):

    # Python packages
    pip install -r requirements.txt

    # Run the server
    py server.py

On unix (requires Python 3.10):

    # System Dependencies
    sudo apt-get update
    sudo apt-get install libusb-1.0-0-dev libudev-dev
    python3.10 -m pip install -U pysqlite3-binary
    python3.10 -c "import pysqlite3; print(pysqlite3.sqlite_version)"

    # Python packages
    python3.10 -m pip3 install -r requirements.txt

    # Run the server
    python3.10 server.py

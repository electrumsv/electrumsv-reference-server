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

What follows is a high-level overview of the different API subsections. 
More detailed documentation of how to use each endpoint will be 
hosted on our swagger API page.

### Endpoint Discovery & Account management (Built-in)
Users of this service will need to open a micropayment channel 
(or use an alternative payment modality) to make pro-rata payments 
for their consumption of this service. Upon account creation, a 
"Master Bearer Token" will be issued which grants access to any
of the other endpoints and trumps the access priviledges of any
other Bearer Tokens (for example the ones generated for each 
Peer Channel that is created).

 Endpoint                                                 | Method | Auth?  | Description
 -------------------------------------------------------- | ------ | ------ | -----------
 `/api/v1/endpoints`                                      | GET    | No     | Retrieves the metadata about the supported APIs
 `/api/v1/account`                                        | GET    | Yes    | Return account information      
 `/api/v1/account/key`                                    | POST   | Special| Post keys and create an account
 `/api/v1/account/channel`                                | POST   | Yes    | Accept the initial version of the contract from the client
 `/api/v1/account/channel`                                | PUT    | Yes    | Accept a contract amendment from the client   
 `/api/v1/account/channel`                                | DELETE | Yes    | Close the payment channel for the client
 `/api/v1/account/funding`                                | GET    | Yes    | Receive the funding transaction from the client

### Peer Channel API (Built-in)
This is a python implementation of C#/ASP.NET Core reference implementation
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

  - The "Master Bearer Token" - grants all access priviledges to any channel
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
    HEADER_SV_URL=http://localhost:8080

These environment variables will essentially cause ElectrumSV-Reference-Server to 
act as a secure reverse proxy for HeaderSV APIs. The `.env` file at the 
top-level of this repository is the default location for loading environment variables
at startup from file.

Endpoint                                                   | Method | Auth?  | Description
 --------------------------------------------------------- | ------ | ------ | -----------         
 `/api/v1/headers/{hash}`                                  | GET    | Yes    | Get a single raw block header by hash
 `/api/v1/headers/by-height/?height=<height>&count=<count>`| GET    | Yes    | Get a batch of headers by height & count
 `/api/v1/chain/tips/websocket`                            | GET    | No     | Get chain tips
 `/api/v1/chain/tips`                                      | GET    | No     | Subscribe to websocket notifications of the new chain tip
 `/api/v1/network/peers`                                   | GET    | No     | Get bitcoin daemon network peers of the running HeaderSV instance


#### Paymail Hosting API
- TBD


## Pro-Rata Payment Protocol
This has not been fully fleshed out but eventually each of these APIs will have
a pricing policy returned alongside the "endpoint discovery" response. 

A micropayment channel will be the preferred payment methodology. Pro-rata
payment for consumption of this service is essential for long-term 
sustainability as the blockchain scales and the economic 
costs of maintaining such services starts to become a factor. It also provides
an incentive for others to run this open source service for ElectrumSV users.

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

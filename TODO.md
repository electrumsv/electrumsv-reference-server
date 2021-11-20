Each todo item is tagged with a short name in the related pieces of code.

* Test client application (this should open up a regtest MAPI port).

* Unit tests.

* get-coinbases: We need a way to get access to coinbase transactions for miner id information.

  We do not have any way to obtain miner id information. What we need to be able to do is get the
  coinbase transaction for each block, in order to get their MAPI endpoint and to get their
  public key (also known as miner id). The public key from a block coinbase can be compared to
  the public key used to sign a JSON envelope response from that MAPI service, in order to show
  that the MAPI response is legitmate.

* utxo-spends: We need a way to register for notifications when a given UTXO is spent.

  Use case: Payment channels. We want to know if the other party broadcasts the initial version
  of the contract intended to give them a full refund.

* safe-dust: We need a way to reliably know what dust limit we should be applying.

  The dust limit used to be assumed to be 546 satoshis, but now it is defined by individual miners.
  It is said to be above 140 satoshis, but who knows what is it.

* script-eval: We need to do script evaluation in a worker thread pool as a standard practice.

  We should have a thread pool where we can send these tasks from the main network asynchronous
  loop, and a timeout where the execution is both interrupted and considered as failed.
  See `esv_reference_server.blockchain.verify_utxo_spend_async`.

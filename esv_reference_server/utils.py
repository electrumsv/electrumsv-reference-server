import logging
import os
import time
from electrumsv_node import electrumsv_node

BITCOIN_NODE_HOST = os.environ.get("BITCOIN_NODE_HOST") or "127.0.0.1"
BITCOIN_NODE_PORT = os.environ.get("BITCOIN_NODE_PORT") or 18332
BITCOIN_NODE_RPCUSER = os.environ.get("BITCOIN_NODE_RPCUSER") or "rpcuser"
BITCOIN_NODE_RPCPASSWORD = os.environ.get("BITCOIN_NODE_RPCPASSWORD") or "rpcpassword"
BITCOIN_NODE_URI = f"http://{BITCOIN_NODE_RPCUSER}:{BITCOIN_NODE_RPCPASSWORD}" \
                   f"@{BITCOIN_NODE_HOST}:{BITCOIN_NODE_PORT}"


logger = logging.getLogger('utils')


def wait_for_initial_node_startup(logger):
    while True:
        try:
            response = electrumsv_node.call_any('getinfo')
            if response.status_code == 200:
                logger.debug(f"Node at: {BITCOIN_NODE_URI} now available.")
                return True
            else:
                logger.debug(f"Node at: {BITCOIN_NODE_URI}. Still unavailable. Retrying...")
                time.sleep(2)
        except Exception as e:
            logger.error(f"still waiting for node on {BITCOIN_NODE_URI}")
            time.sleep(2)

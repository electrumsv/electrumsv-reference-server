# Copyright(c) 2021-2022 Bitcoin Association.
# Distributed under the Open BSV software license, see the accompanying file LICENSE

from __future__ import annotations
import os
import sys
from pathlib import Path
import asyncio
import logging
from logging.handlers import RotatingFileHandler
from typing import cast, Optional

from aiohttp import web

from esv_reference_server.application_state import ApplicationState
from esv_reference_server.server_external import ExternalServer, get_external_server_application
from esv_reference_server.server_internal import InternalServer, get_internal_server_application
from esv_reference_server.constants import DEFAULT_DATABASE_NAME, EXTERNAL_SERVER_HOST, \
    EXTERNAL_SERVER_PORT, HREF_HOST, HREF_PORT, INTERNAL_SERVER_HOST, INTERNAL_SERVER_PORT, Network

MODULE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = Path('logs') / 'esv_reference_server.log'
logger = logging.getLogger("server")

# Silence verbose logging
aiohttp_logger = logging.getLogger("aiohttp")
aiohttp_logger.setLevel(logging.WARNING)
requests_logger = logging.getLogger("urllib3")
requests_logger.setLevel(logging.WARNING)


def create_log_file_if_not_exist(data_path: Path) -> Path:
    full_log_path = data_path / LOG_PATH
    if not full_log_path.exists():
        full_log_path.parent.mkdir(exist_ok=True)
        with open(full_log_path, 'w') as f:
            f.write('')
    return full_log_path


def setup_logging(data_path: Path) -> None:
    full_log_path = create_log_file_if_not_exist(data_path)
    logging.basicConfig(format='%(asctime)s %(levelname)-8s %(name)-24s %(message)s',
        level=logging.DEBUG, datefmt='%Y-%m-%d %H:%M:%S')
    file_handler = RotatingFileHandler(full_log_path, mode='w', backupCount=1, encoding='utf-8')
    formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(name)-24s %(message)s')
    file_handler.setFormatter(formatter)
    logging.root.addHandler(file_handler)

    logger = logging.getLogger("logs")
    logger.debug("File logging path=%s", full_log_path)


def load_dotenv(dotenv_path: Path) -> None:
    with open(dotenv_path, 'r') as f:
        lines = f.readlines()
        for line in lines:
            if line.startswith("#") or line.strip() == '':
                continue

            # Split line on "=" symbol but need to take care of base64 encoded string values.
            split_line = line.strip().split("=")
            key = split_line[0].strip()
            val = split_line[1] + "".join(["=" + part for part in split_line[2:]])
            os.environ[key] = val


def setup_application() -> tuple[Network, Path]:
    # Used for unit testing to override usual configuration
    if not os.getenv("SKIP_DOTENV_FILE") == '1':
        dotenv_path = MODULE_DIR.joinpath('.env')
        load_dotenv(dotenv_path)

    DEFAULT_DATA_PATH = MODULE_DIR / "localdata"
    data_path = Path(os.getenv('REFERENCE_SERVER_DATA_PATH', DEFAULT_DATA_PATH))
    if not data_path.exists():
        data_path.mkdir(parents=True)

    setup_logging(data_path)

    human_readable_network = os.getenv('NETWORK', 'regtest')
    which_network: Network
    if human_readable_network == 'regtest':
        which_network = Network.REGTEST
    elif human_readable_network == 'mainnet':
        which_network = Network.MAINNET
    elif human_readable_network == 'scaling-testnet':
        which_network = Network.STN
    elif human_readable_network == 'testnet':
        which_network = Network.TESTNET
    else:
        print(f"Invalid network '{human_readable_network}'")
        sys.exit(1)

    logger.debug("Running in %s mode", human_readable_network)

    datastore_location = data_path / DEFAULT_DATABASE_NAME
    logger.debug("Datastore location %s", datastore_location)

    return which_network, datastore_location


async def main() -> None:
    which_network, datastore_location = setup_application()
    external_host = cast(str, os.getenv("EXTERNAL_HOST", EXTERNAL_SERVER_HOST))
    external_port_text = os.getenv("EXTERNAL_PORT", EXTERNAL_SERVER_PORT)
    try:
        external_port = int(external_port_text)
    except ValueError:
        print(f"Invalid `EXTERNAL_PORT` value '{external_port_text}'")
        sys.exit(1)
    href_host = cast(str, os.getenv("HREF_HOST", HREF_HOST))
    href_port = int(os.getenv("HREF_PORT", HREF_PORT))

    internal_host = cast(str, os.getenv("INTERNAL_HOST", INTERNAL_SERVER_HOST))
    internal_port_text = os.getenv("INTERNAL_PORT", INTERNAL_SERVER_PORT)
    try:
        internal_port = int(internal_port_text)
    except ValueError:
        print(f"Invalid `INTERNAL_PORT` value '{internal_port_text}'")
        sys.exit(1)

    application_state = ApplicationState(which_network, datastore_location, internal_host,
        internal_port, external_host, external_port, href_host, href_port)

    use_internal_server = os.getenv("EXPOSE_INDEXER_APIS") == "1"
    internal_application: Optional[web.Application] = None
    if use_internal_server:
        assert application_state.indexer_url is not None
        internal_application = get_internal_server_application(application_state)
    external_application = get_external_server_application(application_state)

    await application_state.setup_async(internal_application, external_application)

    internal_server: Optional[InternalServer] = None
    tasks = list[asyncio.Task[None]]()
    if use_internal_server:
        assert internal_application is not None
        internal_server = InternalServer(internal_application, application_state, internal_host,
            internal_port)
        run_internal_server_task = asyncio.create_task(internal_server.run_async())
        tasks.append(run_internal_server_task)

    external_server = ExternalServer(external_application, application_state, external_host,
        external_port)
    run_external_server_task = asyncio.create_task(external_server.run_async())
    tasks.append(run_external_server_task)
    try:
        await asyncio.gather(*tasks)
    finally:
        # In some cases `gather` can exit while leaving a task running, for instance if one
        # task raises an exception out of gather the other task will continue running.
        # - https://docs.python.org/3/library/asyncio-task.html#asyncio.gather
        for task in tasks:
            task.cancel()
        await application_state.teardown_async()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except Exception:
        logger.exception("unexpected exception in __main__")
    finally:
        logger.info("Exiting reference server")

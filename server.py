import os
import sys
from pathlib import Path
import asyncio
import logging
import typing
from logging.handlers import RotatingFileHandler
from typing import Optional

from aiohttp import web

from esv_reference_server.server import get_aiohttp_app
from esv_reference_server.constants import DEFAULT_DATABASE_NAME, SERVER_HOST, SERVER_PORT, \
    STRING_TO_NETWORK_ENUM_MAP

if typing.TYPE_CHECKING:
    from .esv_reference_server.server import ApplicationState


MODULE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = Path('logs') / 'esv_reference_server.log'
logger = logging.getLogger("server")


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



class AiohttpServer:

    def __init__(self, app: web.Application, host: str = SERVER_HOST, port: int = SERVER_PORT) \
            -> None:
        self.runner: Optional[web.AppRunner] = None
        self.app = app
        self.app_state: 'ApplicationState' = app['app_state']
        self.app.on_startup.append(self.on_startup)
        self.app.on_shutdown.append(self.on_shutdown)
        self.app.freeze()  # No further callback modification allowed
        self.host = host
        self.port = port
        self.logger = logging.getLogger("aiohttp-rest-api")

    async def on_startup(self, app: web.Application) -> None:
        pass

    async def on_shutdown(self, app: web.Application) -> None:
        self.logger.debug("Stopping server...")
        await self.app_state.close_aiohttp_session()
        self.app_state.is_alive = False
        self.logger.info("Stopped server")

    async def start(self) -> None:
        self.app_state.is_alive = True
        self.logger.info("Started server on http://%s:%s", self.host, self.port)
        self.runner = web.AppRunner(self.app, access_log=None)
        await self.runner.setup()
        site = web.TCPSite(self.runner, self.host, self.port, reuse_address=True)
        await site.start()
        self.app_state.start_tasks()
        while self.app_state.is_alive:
            await asyncio.sleep(0.5)

    async def stop(self) -> None:
        self.app_state.stop_tasks()
        assert self.runner is not None
        await self.runner.cleanup()


def load_dotenv(dotenv_path: Path) -> None:
    with open(dotenv_path, 'r') as f:
        lines = f.readlines()
        for line in lines:
            if line.startswith("#") or line.strip() == '':
                continue

            # Split line on "=" symbol but need to take care of base64 encoded string values.
            split_line = line.strip().split("=")
            key = split_line[0]
            val = split_line[1] + "".join(["=" + part for part in split_line[2:]])
            os.environ[key] = val


def get_app(host: str = SERVER_HOST, port: int = SERVER_PORT) \
        -> tuple[web.Application, str, int]:
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
    network_enum = STRING_TO_NETWORK_ENUM_MAP[human_readable_network]
    logger.debug("Running in %s mode", human_readable_network)

    datastore_location = data_path / DEFAULT_DATABASE_NAME
    logger.debug("Datastore location %s", datastore_location)

    app = get_aiohttp_app(network_enum, datastore_location, host, port)
    return app


async def main() -> None:
    app, host, port = get_app()
    server = AiohttpServer(app, host, port)
    try:
        await server.start()
    finally:
        await server.stop()

if __name__ == "__main__":
    try:
        asyncio.run(main())
        sys.exit(0)
    except KeyboardInterrupt:
        pass
    except Exception:
        logger.exception("unexpected exception in __main__")
    finally:
        logger.info("ElectrumSV reference server exited")

import argparse
import logging

import uvicorn

from .app import create_app
from .config import Config


def main():
    parser = argparse.ArgumentParser(description="Namespace-limited OpenViking HTTP MCP reader")
    parser.add_argument("--config", required=True, help="Absolute protected TOML file")
    args = parser.parse_args()
    try:
        config = Config.load(args.config)
        app = create_app(config)
    except (ValueError, TypeError, OSError, UnicodeError):
        parser.exit(2, "Invalid protected runtime configuration or secret file.\n")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    uvicorn.run(app, host=config.listen_host, port=config.listen_port,
                proxy_headers=False, access_log=False, log_level="warning",
                limit_concurrency=64, timeout_keep_alive=5, timeout_graceful_shutdown=25)


if __name__ == "__main__":
    main()

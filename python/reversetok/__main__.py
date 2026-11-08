"""Run the authenticated reversetok API with environment configuration."""
from __future__ import annotations

import os

import uvicorn

from .api import create_app_from_env


def main() -> None:
    host = os.environ.get("REVERSETOK_API_HOST", "127.0.0.1")
    port = int(os.environ.get("REVERSETOK_API_PORT", "8787"))
    log_level = os.environ.get("REVERSETOK_LOG_LEVEL", "info")
    uvicorn.run(create_app_from_env(), host=host, port=port, log_level=log_level)


if __name__ == "__main__":
    main()

"""python -m sentinel.server [--port N] [--queue-limit N]

바인드 주소 옵션은 없다 — 127.0.0.1 고정((A) §3.1 `loopback_binding`).
"""
from __future__ import annotations

import argparse

from sentinel.server.config import DEFAULT_PORT, DEFAULT_QUEUE_LIMIT, ServerConfig
from sentinel.server.serve import serve


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m sentinel.server", description=__doc__)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--queue-limit", type=int, default=DEFAULT_QUEUE_LIMIT)
    args = parser.parse_args(argv)
    serve(ServerConfig(port=args.port, queue_limit=args.queue_limit))


if __name__ == "__main__":
    main()

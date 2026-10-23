"""Installed Localghost server command."""

import argparse


def main():
    import uvicorn

    parser = argparse.ArgumentParser(description="Run Localghost and its capture module on this device.")
    parser.add_argument("--port", type=int, default=13666)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535.")
    uvicorn.run("backend.main:app", host="127.0.0.1", port=args.port)

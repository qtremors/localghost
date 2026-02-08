import socket
from contextlib import asynccontextmanager

import pytest
from aiohttp import web

from backend.database import db


@pytest.fixture(autouse=True)
async def isolated_database(tmp_path, monkeypatch):
    monkeypatch.setattr(db, 'DB_PATH', str(tmp_path / 'scans.db'))
    await db.init_db()


@pytest.fixture
def local_server():
    @asynccontextmanager
    async def start(handler, ssl_context=None):
        app = web.Application()
        app.router.add_route('*', '/{path:.*}', handler)
        runner = web.AppRunner(app)
        await runner.setup()
        sock = socket.socket()
        sock.bind(('127.0.0.1', 0))
        site = web.SockSite(runner, sock, ssl_context=ssl_context)
        await site.start()
        port = sock.getsockname()[1]
        try:
            yield f"{'https' if ssl_context else 'http'}://127.0.0.1:{port}"
        finally:
            await runner.cleanup()
    return start

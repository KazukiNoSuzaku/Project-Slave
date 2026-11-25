"""Ops Terminal dashboard server.

FastAPI app that folds the event stream into `DashboardState` and pushes
updates to browsers over a WebSocket. Today the stream is the scripted demo
feed; later it will be the gateway's event bus (design.md §2).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
from collections.abc import AsyncIterator
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from slave.dashboard.state import DashboardState
from slave.schema import Event
from slave.sim.demo_feed import run_demo

STATIC_DIR = Path(__file__).parent / "static"


class Hub:
    """Owns the state and the set of connected WebSocket clients."""

    def __init__(self) -> None:
        self.state = DashboardState()
        self.clients: set[WebSocket] = set()

    async def ingest(self, event: Event) -> list[dict]:
        lines = self.state.apply(event)
        if self.clients:
            await self._broadcast(lines)
        return lines

    async def _broadcast(self, lines: list[dict]) -> None:
        payload = json.dumps({"type": "update", "lines": lines, "snapshot": self.state.snapshot(log_tail=0)},
                             default=str)
        dead = []
        for ws in list(self.clients):
            try:
                await ws.send_text(payload)
            except Exception:  # client went away mid-send
                dead.append(ws)
        for ws in dead:
            self.clients.discard(ws)


def create_app(*, demo: bool = True, speed: float = 1.0, seed: int = 7) -> FastAPI:
    hub = Hub()

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        task = asyncio.create_task(run_demo(hub.ingest, seed=seed, speed=speed)) if demo else None
        try:
            yield
        finally:
            if task:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

    app = FastAPI(title="Project Slave — Ops Terminal", lifespan=lifespan)
    app.state.hub = hub

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/snapshot")
    async def snapshot() -> dict:
        return hub.state.snapshot()

    @app.get("/api/sessions/{session_id}/log")
    async def session_log(session_id: str) -> list[dict]:
        if session_id not in hub.state.sessions:
            raise HTTPException(404, "unknown session")
        return hub.state.session_log(session_id)

    @app.post("/api/events", status_code=202)
    async def post_event(event: Event) -> dict[str, int]:
        """Ingest endpoint for external producers (e.g. the future gateway)."""
        return {"lines": len(await hub.ingest(event))}

    @app.websocket("/ws")
    async def ws(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.send_text(json.dumps({"type": "hello", "snapshot": hub.state.snapshot()}, default=str))
        hub.clients.add(websocket)
        try:
            while True:
                await websocket.receive_text()  # keepalive; client messages ignored
        except WebSocketDisconnect:
            pass
        finally:
            hub.clients.discard(websocket)

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


def main() -> None:
    import uvicorn

    parser = argparse.ArgumentParser(description="Project Slave Ops Terminal dashboard")
    parser.add_argument("--host", default=os.environ.get("SLAVE_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("SLAVE_PORT", "8000")))
    parser.add_argument("--no-demo", action="store_true", help="do not run the scripted demo feed")
    parser.add_argument("--speed", type=float, default=1.0, help="demo playback speed multiplier")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    app = create_app(demo=not args.no_demo, speed=args.speed, seed=args.seed)
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()

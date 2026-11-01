"""The web API and dashboard."""

from __future__ import annotations

import csv
import hmac
import io
import json
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import timedelta
from importlib import resources
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from . import __version__
from .config import Settings
from .engine import KINDS
from .monitor import Monitor
from .notify import Notifier, build_notifier
from .service import utcnow
from .store import Store

log = logging.getLogger("netinv.api")

STATIC = resources.files("netinv") / "static"
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)


class DevicePatch(BaseModel):
    trusted: bool | None = None
    watched: bool | None = None
    label: str | None = Field(default=None, max_length=60)


def _matches(supplied: str | None, expected: str | None) -> bool:
    return bool(supplied and expected and hmac.compare_digest(supplied, expected))


def _bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    return token if scheme.lower() == "bearer" else None


def create_app(
    settings: Settings,
    store: Store,
    monitor: Monitor | None = None,
    *,
    read_token: str | None = None,
    admin_token: str | None = None,
    run_scheduler: bool = True,
) -> FastAPI:
    """Build the app. `monitor` can be injected (tests); otherwise one is created.

    Tokens: with `admin_token` set, changes (trust, label, scan, forget) need it. With
    `read_token` set, reading needs it or the admin token. Both are optional because the default
    setup listens on localhost only.
    """
    notifier: Notifier | None = None
    if monitor is None:
        notifier = build_notifier(settings.notify)
        monitor = Monitor(settings, store, notifier=notifier)
    else:
        notifier = monitor.notifier

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        assert monitor is not None
        try:
            if notifier:
                notifier.start()
            if run_scheduler:
                monitor.start()
            yield
        finally:
            monitor.stop()
            if notifier:
                notifier.close()

    app = FastAPI(title="netinv", version=__version__, lifespan=lifespan)

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        return response

    def can_read(request: Request) -> None:
        if not read_token:
            return
        token = _bearer(request)
        if _matches(token, read_token) or _matches(token, admin_token):
            return
        raise HTTPException(
            401, "a valid token is required", headers={"WWW-Authenticate": "Bearer"}
        )

    def can_write(request: Request) -> None:
        if admin_token and not _matches(_bearer(request), admin_token):
            raise HTTPException(
                401, "the admin token is required", headers={"WWW-Authenticate": "Bearer"}
            )

    read = Depends(can_read)
    write = Depends(can_write)
    assert monitor is not None
    mon = monitor

    # ---- pages

    def static_file(name: str, media_type: str) -> Response:
        return Response((STATIC / name).read_bytes(), media_type=media_type)

    @app.get("/", include_in_schema=False)
    def index() -> Response:
        return static_file("index.html", "text/html; charset=utf-8")

    @app.get("/dashboard.js", include_in_schema=False)
    def script() -> Response:
        return static_file("dashboard.js", "text/javascript; charset=utf-8")

    @app.get("/dashboard.css", include_in_schema=False)
    def style() -> Response:
        return static_file("dashboard.css", "text/css; charset=utf-8")

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__, "scans": mon.status.scans}

    # ---- read

    @app.get("/api/devices", dependencies=[read])
    def devices(unknown: bool = False) -> list[dict[str, Any]]:
        uptime = store.uptime(utcnow(), hours=24)
        result = []
        for device in store.devices():
            if unknown and device.trusted:
                continue
            item = device.as_dict()
            item["uptime_24h"] = uptime.get(device.id)
            result.append(item)
        return result

    @app.get("/api/devices/{device_id}/history", dependencies=[read])
    def history(device_id: str, limit: int = Query(96, ge=1, le=1000)) -> list[dict[str, Any]]:
        if store.device(device_id) is None:
            raise HTTPException(404, "unknown device")
        return [
            {"ts": ts, "up": up, "latency_ms": latency}
            for ts, up, latency in store.history(device_id, limit=limit)
        ]

    @app.get("/api/events", dependencies=[read])
    def events(
        limit: int = Query(50, ge=1, le=1000), kind: str | None = None
    ) -> list[dict[str, Any]]:
        if kind is not None and kind not in KINDS:
            raise HTTPException(422, f"kind must be one of {', '.join(KINDS)}")
        return [e.as_dict() for e in store.events(limit=limit, kind=kind)]

    @app.get("/api/stats", dependencies=[read])
    def stats() -> dict[str, Any]:
        all_devices = store.devices()
        since = (utcnow() - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S") + "Z"
        recent = [e for e in store.events(limit=1000) if e.as_dict()["ts"] >= since]
        return {
            "devices": len(all_devices),
            "online": sum(d.online for d in all_devices),
            "unknown": sum(not d.trusted for d in all_devices),
            "events_24h": len(recent),
            "subnets": [str(n) for n in settings.subnets],
            "interval_seconds": settings.interval,
            "scan": vars(mon.status),
            "notifications": [c.name for c in notifier.channels] if notifier else [],
        }

    @app.get("/api/export", dependencies=[read])
    def export(format: str = Query("csv", pattern="^(csv|json)$")) -> Response:
        rows = [d.as_dict() for d in store.devices()]
        if format == "json":
            return Response(json.dumps(rows, indent=2), media_type="application/json")
        fields = [
            "ip",
            "mac",
            "name",
            "hostname",
            "vendor",
            "label",
            "trusted",
            "watched",
            "online",
            "first_seen",
            "last_seen",
        ]
        out = io.StringIO()
        writer = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            # Spreadsheets run text starting with = + - @ as a formula; names come from the network.
            writer.writerow({k: _spreadsheet_safe(v) for k, v in row.items()})
        return PlainTextResponse(
            out.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="devices.csv"'},
        )

    # ---- change

    @app.patch("/api/devices/{device_id}", dependencies=[write])
    def patch_device(device_id: str, patch: DevicePatch) -> dict[str, Any]:
        if store.device(device_id) is None:
            raise HTTPException(404, "unknown device")
        label = patch.label.strip() if patch.label is not None else None
        store.update_flags(
            device_id,
            trusted=patch.trusted,
            watched=patch.watched,
            label=label or None,
            clear_label=label == "",
        )
        device = store.device(device_id)
        assert device is not None
        return device.as_dict()

    @app.delete("/api/devices/{device_id}", status_code=204, dependencies=[write])
    def forget_device(device_id: str) -> Response:
        if not store.forget(device_id):
            raise HTTPException(404, "unknown device")
        return Response(status_code=204)

    @app.post("/api/scan", dependencies=[write])
    def scan() -> dict[str, Any]:
        changes = mon.scan_now()
        if changes is None:
            raise HTTPException(409, "a scan is already running")
        return {
            "changes": [c.as_event().as_dict() for c in changes],
            "error": mon.status.last_error,
        }

    return app


def _spreadsheet_safe(value: Any) -> Any:
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value

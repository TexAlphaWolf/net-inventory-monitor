"""SQLite storage: devices, events and uptime probes.

Plain `sqlite3`, one short-lived connection per operation (so the scanner thread and the web API
never share one), WAL mode, and a tiny versioned-migration list in place of an ORM.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

TS = "%Y-%m-%dT%H:%M:%S"

# Each entry upgrades the schema by one version (PRAGMA user_version).
MIGRATIONS: list[str] = [
    """
    CREATE TABLE devices (
        id TEXT PRIMARY KEY,
        mac TEXT,
        ip TEXT NOT NULL,
        hostname TEXT,
        vendor TEXT,
        label TEXT,
        trusted INTEGER NOT NULL DEFAULT 0,
        watched INTEGER NOT NULL DEFAULT 0,
        randomized INTEGER NOT NULL DEFAULT 0,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        online INTEGER NOT NULL DEFAULT 1,
        missed INTEGER NOT NULL DEFAULT 0,
        latency_ms REAL,
        details TEXT NOT NULL DEFAULT '{}'
    );
    CREATE TABLE events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        kind TEXT NOT NULL,
        device_id TEXT,
        ip TEXT,
        message TEXT NOT NULL
    );
    CREATE INDEX ix_events_ts ON events (ts);
    CREATE TABLE probes (
        ts TEXT NOT NULL,
        device_id TEXT NOT NULL,
        up INTEGER NOT NULL,
        latency_ms REAL
    );
    CREATE INDEX ix_probes_device_ts ON probes (device_id, ts);
    """,
]


@dataclass
class Device:
    id: str
    ip: str
    first_seen: datetime
    last_seen: datetime
    mac: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    label: str | None = None
    trusted: bool = False
    watched: bool = False
    randomized: bool = False
    online: bool = True
    missed: int = 0
    latency_ms: float | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def name(self) -> str:
        """The best human-readable name we have."""
        return self.label or self.hostname or self.vendor or self.mac or self.ip

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "mac": self.mac,
            "ip": self.ip,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "label": self.label,
            "name": self.name,
            "trusted": self.trusted,
            "watched": self.watched,
            "randomized": self.randomized,
            "online": self.online,
            "first_seen": self.first_seen.strftime(TS) + "Z",
            "last_seen": self.last_seen.strftime(TS) + "Z",
            "latency_ms": self.latency_ms,
            "details": self.details,
        }


@dataclass
class Event:
    kind: str
    message: str
    ts: datetime
    device_id: str | None = None
    ip: str | None = None
    id: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "ts": self.ts.strftime(TS) + "Z",
            "kind": self.kind,
            "device_id": self.device_id,
            "ip": self.ip,
            "message": self.message,
        }


_DEVICE_COLUMNS = (
    "id, mac, ip, hostname, vendor, label, trusted, watched, randomized, first_seen, last_seen, "
    "online, missed, latency_ms, details"
)


def _device(row: tuple[Any, ...]) -> Device:
    return Device(
        id=row[0],
        mac=row[1],
        ip=row[2],
        hostname=row[3],
        vendor=row[4],
        label=row[5],
        trusted=bool(row[6]),
        watched=bool(row[7]),
        randomized=bool(row[8]),
        first_seen=datetime.strptime(row[9], TS),
        last_seen=datetime.strptime(row[10], TS),
        online=bool(row[11]),
        missed=row[12],
        latency_ms=row[13],
        details=json.loads(row[14] or "{}"),
    )


class Store:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.migrate()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        with closing(sqlite3.connect(self.path, timeout=30)) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA foreign_keys=ON")
            with connection:  # commit on success, roll back on error
                yield connection

    # -- schema

    def migrate(self) -> None:
        with self._connect() as db:
            current = db.execute("PRAGMA user_version").fetchone()[0]
            for version in range(current, len(MIGRATIONS)):
                db.executescript(MIGRATIONS[version])
                db.execute(f"PRAGMA user_version = {version + 1}")

    def schema_version(self) -> int:
        with self._connect() as db:
            return int(db.execute("PRAGMA user_version").fetchone()[0])

    # -- devices

    def devices(self) -> list[Device]:
        with self._connect() as db:
            rows = db.execute(f"SELECT {_DEVICE_COLUMNS} FROM devices").fetchall()
        devices = [_device(r) for r in rows]
        devices.sort(key=lambda d: tuple(int(p) for p in d.ip.split(".")))  # numeric IP order
        return devices

    def device(self, device_id: str) -> Device | None:
        with self._connect() as db:
            row = db.execute(
                f"SELECT {_DEVICE_COLUMNS} FROM devices WHERE id = ?", (device_id,)
            ).fetchone()
        return _device(row) if row else None

    def find(self, text: str) -> Device | None:
        """A device by id, MAC, IP or label (the way a person would type it)."""
        needle = text.strip().lower()
        for device in self.devices():
            if needle in {device.id, (device.mac or ""), device.ip, (device.label or "").lower()}:
                return device
        return None

    def save(self, device: Device) -> None:
        with self._connect() as db:
            db.execute(
                f"INSERT OR REPLACE INTO devices ({_DEVICE_COLUMNS}) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    device.id,
                    device.mac,
                    device.ip,
                    device.hostname,
                    device.vendor,
                    device.label,
                    int(device.trusted),
                    int(device.watched),
                    int(device.randomized),
                    device.first_seen.strftime(TS),
                    device.last_seen.strftime(TS),
                    int(device.online),
                    device.missed,
                    device.latency_ms,
                    json.dumps(device.details, sort_keys=True),
                ),
            )

    def update_flags(
        self,
        device_id: str,
        *,
        trusted: bool | None = None,
        watched: bool | None = None,
        label: str | None = None,
        clear_label: bool = False,
    ) -> bool:
        """Change what a person decides about a device. Returns False if it does not exist."""
        device = self.device(device_id)
        if device is None:
            return False
        if trusted is not None:
            device.trusted = trusted
        if watched is not None:
            device.watched = watched
        if clear_label:
            device.label = None
        elif label is not None:
            device.label = label
        self.save(device)
        return True

    def forget(self, device_id: str) -> bool:
        with self._connect() as db:
            cursor = db.execute("DELETE FROM devices WHERE id = ?", (device_id,))
            db.execute("DELETE FROM probes WHERE device_id = ?", (device_id,))
        return cursor.rowcount > 0

    # -- events

    def add_events(self, events: list[Event]) -> None:
        with self._connect() as db:
            db.executemany(
                "INSERT INTO events (ts, kind, device_id, ip, message) VALUES (?,?,?,?,?)",
                [(e.ts.strftime(TS), e.kind, e.device_id, e.ip, e.message) for e in events],
            )

    def events(self, *, limit: int = 100, kind: str | None = None) -> list[Event]:
        query = "SELECT id, ts, kind, device_id, ip, message FROM events"
        args: list[Any] = []
        if kind:
            query += " WHERE kind = ?"
            args.append(kind)
        query += " ORDER BY id DESC LIMIT ?"
        args.append(max(1, min(limit, 1000)))
        with self._connect() as db:
            rows = db.execute(query, args).fetchall()
        return [
            Event(
                id=r[0],
                ts=datetime.strptime(r[1], TS),
                kind=r[2],
                device_id=r[3],
                ip=r[4],
                message=r[5],
            )
            for r in rows
        ]

    # -- probes and uptime

    def add_probes(self, ts: datetime, probes: list[tuple[str, bool, float | None]]) -> None:
        with self._connect() as db:
            db.executemany(
                "INSERT INTO probes (ts, device_id, up, latency_ms) VALUES (?,?,?,?)",
                [(ts.strftime(TS), d, int(up), latency) for d, up, latency in probes],
            )

    def uptime(self, now: datetime, *, hours: int = 24) -> dict[str, float]:
        """Share of probes in the last `hours` in which each device was up (0..100)."""
        since = (now - timedelta(hours=hours)).strftime(TS)
        with self._connect() as db:
            rows = db.execute(
                "SELECT device_id, 100.0 * SUM(up) / COUNT(*) FROM probes WHERE ts >= ? "
                "GROUP BY device_id",
                (since,),
            ).fetchall()
        return {device_id: round(value, 1) for device_id, value in rows}

    def history(self, device_id: str, *, limit: int = 288) -> list[tuple[str, bool, float | None]]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT ts, up, latency_ms FROM probes WHERE device_id = ? "
                "ORDER BY ts DESC LIMIT ?",
                (device_id, limit),
            ).fetchall()
        return [(ts + "Z", bool(up), latency) for ts, up, latency in reversed(rows)]

    # -- retention

    def purge(self, older_than: datetime) -> tuple[int, int]:
        """Delete events and probes older than the given time. Returns (events, probes)."""
        cutoff = older_than.strftime(TS)
        with self._connect() as db:
            events = db.execute("DELETE FROM events WHERE ts < ?", (cutoff,)).rowcount
            probes = db.execute("DELETE FROM probes WHERE ts < ?", (cutoff,)).rowcount
        return events, probes

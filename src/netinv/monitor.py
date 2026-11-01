"""The background loop: scan every N seconds, store, notify, clean up old history."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from datetime import timedelta

from .config import Settings
from .engine import Change
from .notify import Notifier
from .oui import VendorLookup
from .scanner import Scanner
from .service import build_scanner, scan_once, utcnow
from .store import Store

log = logging.getLogger("netinv.monitor")


@dataclass
class ScanStatus:
    running: bool = False
    last_started: str | None = None
    last_finished: str | None = None
    last_duration_s: float | None = None
    last_changes: int = 0
    last_error: str | None = None
    scans: int = 0


class Monitor:
    """Runs scans on a schedule, or on request, never two at once."""

    def __init__(
        self,
        settings: Settings,
        store: Store,
        scanner: Scanner | None = None,
        notifier: Notifier | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.scanner = scanner or build_scanner(settings)
        self.notifier = notifier
        self.vendors = VendorLookup(settings.oui_file)
        self.status = ScanStatus()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def scan_now(self) -> list[Change] | None:
        """Scan once. Returns None if a scan is already running."""
        if not self._lock.acquire(blocking=False):
            return None
        try:
            started = time.monotonic()
            self.status.running = True
            self.status.last_started = utcnow().isoformat() + "Z"
            try:
                changes = scan_once(self.settings, self.store, self.scanner, self.vendors)
                self.status.last_error = None
            except Exception as exc:  # a failed scan must not stop the loop
                self.status.last_error = f"{type(exc).__name__}: {exc}"[:300]
                log.error("scan failed: %s", self.status.last_error)
                return []
            finally:
                self.status.running = False
                self.status.last_finished = utcnow().isoformat() + "Z"
                self.status.last_duration_s = round(time.monotonic() - started, 1)
                self.status.scans += 1
            self.status.last_changes = len(changes)
            for change in changes:
                log.info("%s: %s", change.kind, change.message)
            if self.notifier:
                self.notifier.submit(changes)
            self._retention()
            return changes
        finally:
            self._lock.release()

    def _retention(self) -> None:
        days = self.settings.retention_days
        if days:
            events, probes = self.store.purge(utcnow() - timedelta(days=days))
            if events or probes:
                log.info("retention: removed %d events and %d probes", events, probes)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="netinv-monitor", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.scan_now()
            self._stop.wait(self.settings.interval)

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)

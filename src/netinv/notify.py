"""Notifications: Telegram, a webhook and email.

Design rules, because device names come from the network and can be chosen by an attacker:

* Messages are plain text. Names are stripped of control characters and cut short, and never go
  into an email header.
* Sending never blocks scanning: changes go through a bounded queue to one worker thread, and a
  failing channel is logged (without its URL or credentials) and skipped.
* A flood of changes (a new switch, a router reboot) cannot flood the phone: at most N messages
  per minute, and the rest is reported as one summary.
"""

from __future__ import annotations

import json
import logging
import queue
import smtplib
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from collections.abc import Callable, Iterable
from email.message import EmailMessage
from typing import Any, Protocol
from urllib.parse import urlparse

from .config import ConfigError, NotifySettings
from .engine import SEVERITY, Change

log = logging.getLogger("netinv.notify")

SEVERITIES = ("info", "low", "medium", "high")
WEBHOOK_FORMATS = ("json", "discord")
SMTP_SECURITY = ("starttls", "ssl", "none")
# Going offline or coming back is only news for devices you asked to watch.
WATCHED_ONLY = {"device_offline", "device_online"}


class NotifyError(Exception):
    """Delivery failed. The message never contains a URL or a credential."""


def _clean(value: Any, limit: int = 120) -> str:
    """Printable characters only (no newlines or control codes), cut to `limit`."""
    return "".join(ch for ch in str(value) if ch.isprintable())[:limit]


def format_change(change: Change) -> tuple[str, str]:
    """(subject, plain-text body) for a change."""
    device = change.device
    subject = f"[{_clean(change.severity).upper()}] {_clean(change.message, 150)}"
    lines = [subject, f"Address: {_clean(device.ip)}"]
    if device.mac:
        lines.append(f"MAC: {_clean(device.mac)}")
    if device.vendor:
        lines.append(f"Vendor: {_clean(device.vendor)}")
    if device.hostname:
        lines.append(f"Name: {_clean(device.hostname)}")
    if device.randomized:
        lines.append("The MAC address is randomised (a phone or laptop hiding its identity).")
    lines.append(f"Time: {change.ts:%Y-%m-%d %H:%M:%S} UTC")
    return subject, "\n".join(lines)


def change_json(change: Change) -> dict[str, Any]:
    return {
        "ts": change.ts.isoformat() + "Z",
        "kind": change.kind,
        "severity": change.severity,
        "message": change.message,
        "device": change.device.as_dict(),
    }


# ----------------------------------------------------------------------------- channels


class Channel(Protocol):
    name: str

    def send(self, subject: str, body: str, alert: dict[str, Any] | None) -> None: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: an error is better than sending a token somewhere new."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _post_json(url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float) -> None:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.build_opener(_NoRedirect).open(request, timeout=timeout) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        exc.close()
        raise NotifyError(f"HTTP {exc.code}") from None
    except urllib.error.URLError as exc:
        raise NotifyError(type(exc.reason).__name__) from None
    except (OSError, ValueError) as exc:
        raise NotifyError(type(exc).__name__) from None
    if not 200 <= status < 300:
        raise NotifyError(f"HTTP {status}")


class TelegramChannel:
    name = "telegram"

    def __init__(
        self,
        token: str,
        chat_id: str,
        base_url: str = "https://api.telegram.org",
        timeout: float = 10,
    ) -> None:
        self._url = f"{base_url.rstrip('/')}/bot{token}/sendMessage"
        self._chat_id = chat_id
        self._timeout = timeout

    def send(self, subject: str, body: str, alert: dict[str, Any] | None) -> None:
        # No parse_mode: Telegram shows the text as it is, so log data cannot inject markup.
        payload = {"chat_id": self._chat_id, "text": body[:4000], "disable_web_page_preview": True}
        _post_json(self._url, payload, {}, self._timeout)


class WebhookChannel:
    name = "webhook"

    def __init__(
        self, url: str, token: str | None = None, fmt: str = "json", timeout: float = 10
    ) -> None:
        self._url = url
        self._token = token
        self._format = fmt
        self._timeout = timeout

    def send(self, subject: str, body: str, alert: dict[str, Any] | None) -> None:
        if self._format == "discord":
            payload: dict[str, Any] = {"content": body[:1900]}
        else:
            # "text" is what Slack, Mattermost and Rocket.Chat incoming webhooks read.
            payload = {"text": body, "change": alert}
        headers = {"Authorization": f"Bearer {self._token}"} if self._token else {}
        _post_json(self._url, payload, headers, self._timeout)


class EmailChannel:
    name = "email"

    def __init__(
        self,
        host: str,
        port: int,
        sender: str,
        recipients: Iterable[str],
        security: str = "starttls",
        user: str | None = None,
        password: str | None = None,
        timeout: float = 15,
    ) -> None:
        self._host, self._port, self._security = host, port, security
        self._sender, self._recipients = sender, list(recipients)
        self._user, self._password = user, password
        self._timeout = timeout

    def send(self, subject: str, body: str, alert: dict[str, Any] | None) -> None:
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = self._sender
        message["To"] = ", ".join(self._recipients)
        message.set_content(body)
        try:
            context = ssl.create_default_context()
            if self._security == "ssl":
                smtp: smtplib.SMTP = smtplib.SMTP_SSL(
                    self._host, self._port, timeout=self._timeout, context=context
                )
            else:
                smtp = smtplib.SMTP(self._host, self._port, timeout=self._timeout)
            with smtp:
                if self._security == "starttls":
                    smtp.starttls(context=context)
                if self._user:
                    smtp.login(self._user, self._password or "")
                smtp.send_message(message)
        except (smtplib.SMTPException, OSError, ValueError) as exc:
            raise NotifyError(type(exc).__name__) from None


# ----------------------------------------------------------------------------- notifier


class Notifier:
    """Filters changes, applies the rate limit and delivers them on a background thread."""

    QUEUE_SIZE = 1000

    def __init__(
        self,
        channels: list[Channel],
        settings: NotifySettings,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.channels = channels
        self._rank = SEVERITIES.index(settings.min_severity)
        self._max_per_minute = settings.max_per_minute
        self._clock = clock
        self._recent: deque[float] = deque()
        self._suppressed = 0
        self._queue: queue.Queue[Change | None] = queue.Queue(self.QUEUE_SIZE)
        self._thread: threading.Thread | None = None

    def wanted(self, change: Change) -> bool:
        if change.kind == "baseline":
            return False
        if change.kind in WATCHED_ONLY and not change.device.watched:
            return False
        return SEVERITIES.index(SEVERITY[change.kind]) >= self._rank

    def submit(self, changes: Iterable[Change]) -> int:
        """Queue the changes that deserve a message. Never blocks. Returns how many."""
        queued = 0
        for change in changes:
            if not self.wanted(change):
                continue
            try:
                self._queue.put_nowait(change)
                queued += 1
            except queue.Full:
                log.warning("notification queue is full; dropping changes")
                break
        return queued

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="netinv-notify", daemon=True)
        self._thread.start()

    def close(self, timeout: float = 5.0) -> None:
        if self._thread is None:
            return
        try:
            self._queue.put(None, timeout=1.0)
        except queue.Full:
            return
        self._thread.join(timeout)

    def _run(self) -> None:
        while True:
            try:
                item = self._queue.get(timeout=60.0 if self._suppressed else None)
            except queue.Empty:
                self._flush_summary()
                continue
            if item is None:
                self._flush_summary()
                return
            self.deliver(item)

    def _has_room(self) -> bool:
        now = self._clock()
        while self._recent and now - self._recent[0] >= 60.0:
            self._recent.popleft()
        return len(self._recent) < self._max_per_minute

    def deliver(self, change: Change) -> bool:
        """Send one change now (rate limited). Returns False when it was held back."""
        if not self._has_room():
            self._suppressed += 1
            return False
        self._flush_summary()
        if not self._has_room():  # the summary used the last free slot
            self._suppressed += 1
            return False
        self._recent.append(self._clock())
        subject, body = format_change(change)
        self._send_all(subject, body, change_json(change))
        return True

    def _flush_summary(self) -> None:
        if not self._suppressed or not self._has_room():
            return
        count, self._suppressed = self._suppressed, 0
        self._recent.append(self._clock())
        subject = f"netinv: {count} more change{'s' if count != 1 else ''} not sent"
        body = (
            f"{subject}\nThe limit of {self._max_per_minute} messages per minute was reached.\n"
            "Open the dashboard to see them all."
        )
        self._send_all(subject, body, None)

    def _send_all(self, subject: str, body: str, payload: dict[str, Any] | None) -> None:
        for channel in self.channels:
            try:
                channel.send(subject, body, payload)
            except Exception as exc:  # one broken channel must not stop the others
                log.warning("notification via %s failed: %s", channel.name, _failure(exc))

    def send_test(self) -> list[tuple[str, str | None]]:
        """Send a test message on every channel. Returns (channel, error or None)."""
        results: list[tuple[str, str | None]] = []
        for channel in self.channels:
            try:
                channel.send("netinv test", "netinv test message: notifications work.", None)
                results.append((channel.name, None))
            except Exception as exc:
                results.append((channel.name, _failure(exc)))
        return results


def _failure(exc: Exception) -> str:
    """A description of a failure that cannot contain a URL or a credential."""
    return str(exc) if isinstance(exc, NotifyError) else type(exc).__name__


# ------------------------------------------------------------------------------ building


def _check_url(url: str) -> None:
    parts = urlparse(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ConfigError("NETINV_WEBHOOK_URL must be an http:// or https:// URL")


def build_notifier(settings: NotifySettings) -> Notifier | None:
    """Create the notifier for the configured channels, or None when there are none."""
    if settings.min_severity not in SEVERITIES:
        raise ConfigError(f"NETINV_NOTIFY_MIN_SEVERITY must be one of {', '.join(SEVERITIES)}")
    channels: list[Channel] = []

    if settings.telegram_token or settings.telegram_chat_id:
        if not (settings.telegram_token and settings.telegram_chat_id):
            raise ConfigError("Telegram needs both NETINV_TELEGRAM_TOKEN and _CHAT_ID")
        channels.append(TelegramChannel(settings.telegram_token, settings.telegram_chat_id))

    if settings.webhook_url:
        _check_url(settings.webhook_url)
        if settings.webhook_format not in WEBHOOK_FORMATS:
            raise ConfigError(f"NETINV_WEBHOOK_FORMAT must be one of {', '.join(WEBHOOK_FORMATS)}")
        channels.append(
            WebhookChannel(settings.webhook_url, settings.webhook_token, settings.webhook_format)
        )

    if settings.smtp_host:
        if not (settings.smtp_from and settings.smtp_to):
            raise ConfigError("Email needs NETINV_SMTP_FROM and NETINV_SMTP_TO")
        if settings.smtp_security not in SMTP_SECURITY:
            raise ConfigError(f"NETINV_SMTP_SECURITY must be one of {', '.join(SMTP_SECURITY)}")
        if settings.smtp_password and not settings.smtp_user:
            raise ConfigError("NETINV_SMTP_PASSWORD needs NETINV_SMTP_USER")
        channels.append(
            EmailChannel(
                settings.smtp_host,
                settings.smtp_port,
                settings.smtp_from,
                settings.smtp_to,
                settings.smtp_security,
                settings.smtp_user,
                settings.smtp_password,
            )
        )

    return Notifier(channels, settings) if channels else None

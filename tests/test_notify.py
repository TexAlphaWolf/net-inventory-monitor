from __future__ import annotations

import json
import smtplib
import urllib.error

import pytest
from conftest import T0

from netinv import notify
from netinv.config import ConfigError, NotifySettings
from netinv.engine import Change
from netinv.notify import (
    EmailChannel,
    Notifier,
    NotifyError,
    TelegramChannel,
    WebhookChannel,
    build_notifier,
    change_json,
    format_change,
)
from netinv.store import Device


def make_change(kind="new_device", watched=False, **overrides) -> Change:
    values = dict(
        id="aa:bb:cc:dd:ee:01",
        mac="aa:bb:cc:dd:ee:01",
        ip="192.168.1.99",
        first_seen=T0,
        last_seen=T0,
        hostname="evil\nhost",
        vendor="Acme",
        randomized=True,
        watched=watched,
    )
    return Change(kind, Device(**{**values, **overrides}), "New device: 192.168.1.99", T0)


class FakeChannel:
    name = "fake"

    def __init__(self, fail: Exception | None = None):
        self.sent: list[tuple[str, str, dict | None]] = []
        self.fail = fail

    def send(self, subject, body, alert):
        if self.fail:
            raise self.fail
        self.sent.append((subject, body, alert))


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def notifier(channel=None, **settings):
    clock = Clock()
    chan = channel or FakeChannel()
    return Notifier([chan], NotifySettings(**settings), clock=clock), chan, clock


def test_message_is_plain_text_and_cleaned():
    subject, body = format_change(make_change())
    assert subject.startswith("[MEDIUM] New device")
    assert "Name: evilhost" in body and "\n\n" not in body
    assert "randomised" in body and "Vendor: Acme" in body and "MAC: aa:bb" in body


def test_payload_contains_the_device():
    data = change_json(make_change())
    assert data["kind"] == "new_device" and data["device"]["ip"] == "192.168.1.99"
    json.dumps(data)


@pytest.mark.parametrize(
    "kind, watched, min_severity, expected",
    [
        ("new_device", False, "medium", True),
        ("new_device", False, "high", False),
        ("ip_takeover", False, "high", True),
        ("ip_changed", False, "medium", False),
        ("device_offline", False, "low", False),  # not watched: not news
        ("device_offline", True, "low", True),
        ("device_online", True, "low", False),  # info is below low
        ("device_online", True, "info", True),
        ("baseline", True, "info", False),
    ],
)
def test_filtering(kind, watched, min_severity, expected):
    n, _, _ = notifier(min_severity=min_severity)
    assert n.wanted(make_change(kind, watched=watched)) is expected


def test_submit_counts_queued_changes():
    n, _, _ = notifier()
    assert n.submit([make_change(), make_change("device_online"), make_change()]) == 2


def test_full_queue_drops_instead_of_blocking(caplog):
    n, _, _ = notifier()
    n.QUEUE_SIZE = 1
    n._queue = notify.queue.Queue(1)
    assert n.submit([make_change(), make_change()]) == 1
    assert "queue is full" in caplog.text


def test_rate_limit_and_summary():
    n, chan, clock = notifier(max_per_minute=2)
    results = [n.deliver(make_change()) for _ in range(5)]
    assert results == [True, True, False, False, False]
    clock.t += 61
    assert n.deliver(make_change()) is True
    assert any("3 more changes not sent" in s for s, _, _ in chan.sent)


def test_a_failing_channel_does_not_stop_the_others(caplog):
    bad = FakeChannel(fail=RuntimeError("secret-token-in-url"))
    good = FakeChannel()
    n = Notifier([bad, good], NotifySettings())
    n.deliver(make_change())
    assert len(good.sent) == 1
    assert "secret-token-in-url" not in caplog.text and "RuntimeError" in caplog.text


def test_send_test_reports_each_channel():
    n = Notifier([FakeChannel(), FakeChannel(fail=NotifyError("HTTP 401"))], NotifySettings())
    assert n.send_test() == [("fake", None), ("fake", "HTTP 401")]


def test_worker_thread_delivers_and_closes():
    n, chan, _ = notifier()
    n.start()
    n.submit([make_change()])
    n.close()
    assert len(chan.sent) == 1
    Notifier([], NotifySettings()).close()  # never started: nothing to do


def test_worker_flushes_a_summary_on_close():
    n, chan, _ = notifier(max_per_minute=1)
    n.start()
    n.submit([make_change(), make_change()])
    n.close()
    assert len(chan.sent) >= 1


# ---- channels, against fake network code


class FakeResponse:
    def __init__(self, status=200):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeOpener:
    def __init__(self, outcome):
        self.outcome = outcome
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


def patch_opener(monkeypatch, outcome):
    opener = FakeOpener(outcome)
    monkeypatch.setattr(notify.urllib.request, "build_opener", lambda *handlers: opener)
    return opener


def test_telegram_sends_plain_text(monkeypatch):
    opener = patch_opener(monkeypatch, FakeResponse())
    TelegramChannel("TOKEN", "42").send("s", "hello", None)
    request = opener.requests[0]
    assert "botTOKEN/sendMessage" in request.full_url
    payload = json.loads(request.data)
    assert payload["text"] == "hello" and "parse_mode" not in payload


def test_webhook_formats_and_token(monkeypatch):
    opener = patch_opener(monkeypatch, FakeResponse())
    WebhookChannel("https://hooks.example/x", "tok").send("s", "body", {"a": 1})
    request = opener.requests[0]
    assert json.loads(request.data) == {"text": "body", "change": {"a": 1}}
    assert request.get_header("Authorization") == "Bearer tok"
    WebhookChannel("https://hooks.example/x", fmt="discord").send("s", "body", None)
    assert json.loads(opener.requests[1].data) == {"content": "body"}


def test_http_failures_never_leak_the_url(monkeypatch):
    url = "https://hooks.example/SECRET"
    error = urllib.error.HTTPError(url, 500, "boom", {}, None)
    patch_opener(monkeypatch, error)
    with pytest.raises(NotifyError) as caught:
        WebhookChannel(url).send("s", "b", None)
    assert str(caught.value) == "HTTP 500" and "SECRET" not in str(caught.value)
    patch_opener(monkeypatch, urllib.error.URLError(ConnectionRefusedError()))
    with pytest.raises(NotifyError, match="ConnectionRefusedError"):
        WebhookChannel(url).send("s", "b", None)
    patch_opener(monkeypatch, TimeoutError())
    with pytest.raises(NotifyError, match="TimeoutError"):
        WebhookChannel(url).send("s", "b", None)
    patch_opener(monkeypatch, FakeResponse(status=302))
    with pytest.raises(NotifyError, match="HTTP 302"):
        WebhookChannel(url).send("s", "b", None)


def test_redirects_are_not_followed():
    handler = notify._NoRedirect()
    assert handler.redirect_request() is None


class FakeSMTP:
    instances: list[FakeSMTP] = []

    def __init__(self, host, port, timeout, context=None):
        self.actions = []
        self.context = context
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context):
        self.actions.append("starttls")

    def login(self, user, password):
        self.actions.append(("login", user, password))

    def send_message(self, message):
        self.actions.append(("send", message))


@pytest.mark.parametrize("security", ["starttls", "ssl", "none"])
def test_email_channel(monkeypatch, security):
    FakeSMTP.instances = []
    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(notify.smtplib, "SMTP_SSL", FakeSMTP)
    EmailChannel("smtp.example", 587, "a@x", ["b@x", "c@x"], security, "user", "pw").send(
        "Subject", "Body", None
    )
    actions = FakeSMTP.instances[0].actions
    assert ("starttls" in actions) is (security == "starttls")
    assert ("login", "user", "pw") in actions
    message = actions[-1][1]
    assert message["To"] == "b@x, c@x" and message["Subject"] == "Subject"


def test_email_errors_are_summarised(monkeypatch):
    def boom(*a, **k):
        raise smtplib.SMTPAuthenticationError(535, b"bad password hunter2")

    monkeypatch.setattr(notify.smtplib, "SMTP", boom)
    with pytest.raises(NotifyError) as caught:
        EmailChannel("h", 587, "a@x", ["b@x"]).send("s", "b", None)
    assert "hunter2" not in str(caught.value)


# ---- building from settings


def test_no_channels_means_no_notifier():
    assert build_notifier(NotifySettings()) is None


def test_build_all_channels():
    built = build_notifier(
        NotifySettings(
            telegram_token="t",
            telegram_chat_id="1",
            webhook_url="https://x.example/h",
            smtp_host="smtp.example",
            smtp_from="a@x",
            smtp_to=("b@x",),
        )
    )
    assert [c.name for c in built.channels] == ["telegram", "webhook", "email"]


@pytest.mark.parametrize(
    "settings, message",
    [
        (dict(min_severity="loud", webhook_url="https://x"), "MIN_SEVERITY"),
        (dict(telegram_token="t"), "both"),
        (dict(webhook_url="ftp://x"), "http"),
        (dict(webhook_url="https://x", webhook_format="xml"), "FORMAT"),
        (dict(smtp_host="h"), "SMTP_FROM"),
        (dict(smtp_host="h", smtp_from="a@x", smtp_to=("b@x",), smtp_security="tls"), "SECURITY"),
        (dict(smtp_host="h", smtp_from="a@x", smtp_to=("b@x",), smtp_password="p"), "SMTP_USER"),
    ],
)
def test_bad_notification_settings(settings, message):
    with pytest.raises(ConfigError, match=message):
        build_notifier(NotifySettings(**settings))

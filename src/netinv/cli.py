"""Command line interface: scan, devices, events, trust, label, watch, forget, oui-update."""

from __future__ import annotations

import argparse
import logging
import os
import ssl
import sys
import urllib.error
import urllib.request
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .config import ConfigError, load_db_path, load_env_file, load_settings
from .engine import Change
from .scanner import ScanError
from .service import scan_once
from .store import Device, Store

IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"


def _table(rows: list[list[str]], headers: list[str]) -> str:
    widths = [max(len(str(x)) for x in col) for col in zip(headers, *rows, strict=False)]
    lines = ["  ".join(h.ljust(w) for h, w in zip(headers, widths, strict=True)).rstrip()]
    lines += [
        "  ".join(str(c).ljust(w) for c, w in zip(r, widths, strict=True)).rstrip() for r in rows
    ]
    return "\n".join(lines)


def _flags(device: Device) -> str:
    flags = ["trusted" if device.trusted else "UNKNOWN"]
    if device.watched:
        flags.append("watched")
    if device.randomized:
        flags.append("random-mac")
    if device.details.get("self"):
        flags.append("this-machine")
    return ",".join(flags)


def print_changes(changes: list[Change]) -> None:
    if not changes:
        print("no changes")
    for change in changes:
        print(f"[{change.severity.upper()}] {change.message}")


def _store(path: Path | None = None) -> Store:
    return Store(path or load_db_path())


def _need(store: Store, text: str) -> Device:
    device = store.find(text)
    if device is None:
        raise ConfigError(f"no device matches {text!r} (use a MAC, an IP or a label)")
    return device


def _cmd_scan(args: argparse.Namespace) -> int:
    settings = load_settings()
    store = Store(settings.db_path)
    networks = ", ".join(str(n) for n in settings.subnets)
    print(f"scanning {networks} ...")
    changes = scan_once(settings, store)
    print_changes(changes)
    if not store.devices():
        print(
            "warning: no device was found. Check NETINV_SUBNETS, and that the machine is on that "
            "network and `ping` works.",
            file=sys.stderr,
        )
    return 0


def _cmd_devices(args: argparse.Namespace) -> int:
    store = _store()
    devices = store.devices()
    if args.unknown:
        devices = [d for d in devices if not d.trusted]
    rows = [
        [d.ip, d.mac or "-", d.name, d.vendor or "-", "up" if d.online else "down", _flags(d)]
        for d in devices
    ]
    print(_table(rows, ["IP", "MAC", "NAME", "VENDOR", "STATE", "FLAGS"]) if rows else "no devices")
    return 0


def _cmd_events(args: argparse.Namespace) -> int:
    for event in _store().events(limit=args.limit, kind=args.kind):
        print(f"{event.ts:%Y-%m-%d %H:%M:%S}  {event.kind:<15} {event.message}")
    return 0


def _cmd_mark(args: argparse.Namespace) -> int:
    store = _store()
    if args.device == "all" and args.command in ("trust", "untrust"):
        everyone = store.devices()
        for device in everyone:
            store.update_flags(device.id, trusted=args.command == "trust")
        print(f"{args.command}: {len(everyone)} devices")
        return 0
    device = _need(store, args.device)
    if args.command in ("trust", "untrust"):
        store.update_flags(device.id, trusted=args.command == "trust")
    else:
        store.update_flags(device.id, watched=args.command == "watch")
    print(f"{args.command}: {device.name} ({device.ip})")
    return 0


def _cmd_label(args: argparse.Namespace) -> int:
    store = _store()
    device = _need(store, args.device)
    store.update_flags(
        device.id, label=args.text.strip()[:60] or None, clear_label=not args.text.strip()
    )
    print(
        f"labelled {device.ip} as {args.text.strip()!r}" if args.text.strip() else "label removed"
    )
    return 0


def _cmd_forget(args: argparse.Namespace) -> int:
    store = _store()
    device = _need(store, args.device)
    store.forget(device.id)
    print(f"forgot {device.name} ({device.ip})")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    import uvicorn

    from .api import create_app

    settings = load_settings()
    app = create_app(
        settings,
        Store(settings.db_path),
        read_token=settings.read_token,
        admin_token=settings.admin_token,
    )
    # One worker: the scheduler and the in-memory scan lock live in this process.
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


def _cmd_notify_test(args: argparse.Namespace) -> int:
    from .notify import build_notifier

    notifier = build_notifier(load_settings().notify)
    if notifier is None:
        print("no notification channel is configured (see docs/configuration.md)")
        return 1
    failed = False
    for channel, error in notifier.send_test():
        print(f"{channel}: {'ok' if error is None else 'FAILED - ' + error}")
        failed = failed or error is not None
    return 1 if failed else 0


def _ssl_context() -> ssl.SSLContext:
    """The system's trusted CAs, plus NETINV_CA_BUNDLE if set. Verification is never turned off."""
    bundle = os.environ.get("NETINV_CA_BUNDLE", "").strip()
    return ssl.create_default_context(cafile=bundle or None)


def _cmd_oui_update(args: argparse.Namespace) -> int:
    target = Path(args.output) if args.output else load_db_path().parent / "oui.csv"
    target.parent.mkdir(parents=True, exist_ok=True)
    print(f"downloading {IEEE_OUI_URL} ...")
    request = urllib.request.Request(IEEE_OUI_URL, headers={"User-Agent": f"netinv/{__version__}"})
    try:
        with urllib.request.urlopen(request, timeout=60, context=_ssl_context()) as response:  # noqa: S310 - fixed https URL
            data = response.read(20_000_000)
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        hint = ""
        if isinstance(reason, ssl.SSLCertVerificationError):
            hint = (
                "\nSomething on this network or computer (an antivirus, a proxy) re-signs HTTPS "
                "traffic with a certificate Python does not trust. Certificate checks are never "
                "switched off here; instead download the file in your browser and save it as "
                f"{target}"
            )
        raise ConfigError(
            f"could not download {IEEE_OUI_URL}: {type(reason).__name__}{hint}"
        ) from None
    target.write_bytes(data)
    print(f"saved {len(data) // 1024} KiB to {target}; it is used automatically")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netinv", description="Network inventory and monitor.")
    parser.add_argument("--version", action="version", version=f"netinv {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("scan", help="scan once and print what changed").set_defaults(func=_cmd_scan)

    p = sub.add_parser("run", help="scan on a schedule and serve the dashboard")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8090)
    p.set_defaults(func=_cmd_run)

    sub.add_parser("notify-test", help="send a test message on every channel").set_defaults(
        func=_cmd_notify_test
    )

    p = sub.add_parser("devices", help="list the inventory")
    p.add_argument("--unknown", action="store_true", help="only devices you have not trusted")
    p.set_defaults(func=_cmd_devices)

    p = sub.add_parser("events", help="show the change history")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--kind", help="for example new_device")
    p.set_defaults(func=_cmd_events)

    for name, text in [
        ("trust", "mark a device as known"),
        ("untrust", "mark a device as unknown again"),
        ("watch", "alert when this device goes offline"),
        ("unwatch", "stop alerting about this device being offline"),
    ]:
        p = sub.add_parser(name, help=text)
        p.add_argument("device", help="MAC, IP or label (trust and untrust also accept: all)")
        p.set_defaults(func=_cmd_mark)

    p = sub.add_parser("label", help="give a device a name (empty text removes it)")
    p.add_argument("device", help="MAC, IP or label")
    p.add_argument("text")
    p.set_defaults(func=_cmd_label)

    p = sub.add_parser("forget", help="remove a device and its history")
    p.add_argument("device", help="MAC, IP or label")
    p.set_defaults(func=_cmd_forget)

    p = sub.add_parser("oui-update", help="download the IEEE vendor list")
    p.add_argument("-o", "--output", help="default: oui.csv next to the database")
    p.set_defaults(func=_cmd_oui_update)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    args = build_parser().parse_args(argv)
    load_env_file()
    try:
        return int(args.func(args))
    except (ConfigError, ScanError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

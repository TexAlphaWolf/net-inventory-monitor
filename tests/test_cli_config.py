import pytest
from conftest import host

from netinv import cli, service
from netinv.config import ConfigError, load_settings
from netinv.scanner import ScanError
from netinv.store import Store

ENV = (
    "NETINV_SUBNETS",
    "NETINV_DB",
    "NETINV_INTERVAL",
    "NETINV_OFFLINE_AFTER",
    "NETINV_MAX_HOSTS",
    "NETINV_ALLOW_PUBLIC",
    "NETINV_RESOLVE_NAMES",
    "NETINV_OUI_FILE",
    "NETINV_WORKERS",
    "NETINV_PING_TIMEOUT_MS",
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)  # a real .env in the project folder must not leak into tests
    for name in ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NETINV_SUBNETS", "192.168.1.0/24")
    monkeypatch.setenv("NETINV_DB", str(tmp_path / "cli.db"))


class FakeScanner:
    def __init__(self, hosts):
        self.hosts = hosts

    def scan(self, networks):
        return self.hosts


def use_scanner(monkeypatch, hosts):
    monkeypatch.setattr(service, "build_scanner", lambda settings: FakeScanner(hosts))


def run(*argv):
    return cli.main(list(argv))


def test_settings_defaults():
    s = load_settings()
    assert [str(n) for n in s.subnets] == ["192.168.1.0/24"]
    assert (s.interval, s.offline_after, s.workers, s.resolve_names) == (300, 3, 64, True)
    assert s.oui_file is None


def test_settings_from_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("NETINV_INTERVAL", "60")
    monkeypatch.setenv("NETINV_RESOLVE_NAMES", "no")
    monkeypatch.setenv("NETINV_OUI_FILE", str(tmp_path / "oui.csv"))
    s = load_settings()
    assert s.interval == 60 and not s.resolve_names and s.oui_file == tmp_path / "oui.csv"


@pytest.mark.parametrize(
    "name, value, message",
    [
        ("NETINV_SUBNETS", "", "no subnet"),
        ("NETINV_SUBNETS", "8.8.8.0/24", "private"),
        ("NETINV_INTERVAL", "soon", "whole number"),
        ("NETINV_INTERVAL", "1", "at least 10"),
        ("NETINV_RESOLVE_NAMES", "maybe", "true or false"),
    ],
)
def test_bad_settings_are_explained(monkeypatch, name, value, message):
    monkeypatch.setenv(name, value)
    with pytest.raises(ConfigError, match=message):
        load_settings()


def test_scan_then_list(monkeypatch, capsys):
    use_scanner(monkeypatch, [host("192.168.1.1", "a4:2b:b0:11:22:33")])
    assert run("scan") == 0
    assert "First scan" in capsys.readouterr().out
    use_scanner(
        monkeypatch,
        [host("192.168.1.1", "a4:2b:b0:11:22:33"), host("192.168.1.9", "00:11:22:33:44:55")],
    )
    assert run("scan") == 0
    assert "[MEDIUM] New device" in capsys.readouterr().out
    assert run("scan") == 0
    assert "no changes" in capsys.readouterr().out
    assert run("devices") == 0
    out = capsys.readouterr().out
    assert "192.168.1.9" in out and "UNKNOWN" in out and "trusted" in out
    assert run("devices", "--unknown") == 0
    assert "192.168.1.1 " not in capsys.readouterr().out
    assert run("events", "--kind", "new_device") == 0
    assert "New device" in capsys.readouterr().out


def test_trust_label_watch_forget(monkeypatch, capsys, tmp_path):
    use_scanner(monkeypatch, [host("192.168.1.1", "a4:2b:b0:11:22:33")])
    run("scan")
    use_scanner(monkeypatch, [host("192.168.1.9", "00:11:22:33:44:55")])
    run("scan")
    capsys.readouterr()
    store = Store(tmp_path / "cli.db")
    assert run("trust", "192.168.1.9") == 0
    assert store.device("00:11:22:33:44:55").trusted
    assert run("untrust", "00:11:22:33:44:55") == 0
    assert not store.device("00:11:22:33:44:55").trusted
    assert run("watch", "192.168.1.9") == 0 and store.device("00:11:22:33:44:55").watched
    assert run("unwatch", "192.168.1.9") == 0 and not store.device("00:11:22:33:44:55").watched
    assert run("label", "192.168.1.9", "Guest phone") == 0
    assert store.device("00:11:22:33:44:55").label == "Guest phone"
    assert run("label", "guest phone", "") == 0
    assert store.device("00:11:22:33:44:55").label is None
    assert run("forget", "192.168.1.9") == 0
    assert store.device("00:11:22:33:44:55") is None
    capsys.readouterr()
    assert run("trust", "192.168.1.9") == 2
    assert "no device matches" in capsys.readouterr().err


def test_errors_exit_with_code_2(monkeypatch, capsys):
    monkeypatch.setenv("NETINV_SUBNETS", "")
    assert run("scan") == 2
    assert "no subnet" in capsys.readouterr().err


def test_scan_errors_are_reported(monkeypatch, capsys):
    class Broken:
        def scan(self, networks):
            raise ScanError("ping missing")

    monkeypatch.setattr(service, "build_scanner", lambda settings: Broken())
    assert run("scan") == 2
    assert "ping missing" in capsys.readouterr().err


def test_empty_inventory(capsys):
    assert run("devices") == 0
    assert "no devices" in capsys.readouterr().out


def test_version(capsys):
    with pytest.raises(SystemExit):
        run("--version")
    assert "netinv" in capsys.readouterr().out


def test_oui_update_downloads_to_a_file(monkeypatch, tmp_path, capsys):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return b"Registry,Assignment\nMA-L,001122,Example\n"

    monkeypatch.setattr(cli.urllib.request, "urlopen", lambda *a, **k: Response())
    target = tmp_path / "sub" / "oui.csv"
    assert run("oui-update", "-o", str(target)) == 0
    assert b"Example" in target.read_bytes()
    assert "used automatically" in capsys.readouterr().out
    assert run("oui-update") == 0  # default: next to the database
    assert (tmp_path / "oui.csv").exists()


def test_build_scanner_uses_settings():
    scanner = service.build_scanner(load_settings())
    assert scanner.workers == 64 and scanner.timeout_ms == 800


def test_downloaded_oui_file_is_found_next_to_the_database(tmp_path):
    assert load_settings().oui_file is None
    (tmp_path / "oui.csv").write_text("x")
    assert load_settings().oui_file == tmp_path / "oui.csv"


def test_trust_all_and_untrust_all(monkeypatch, capsys, tmp_path):
    use_scanner(monkeypatch, [host("192.168.1.1", "a4:2b:b0:11:22:33")])
    run("scan")
    use_scanner(monkeypatch, [host("192.168.1.9", "00:11:22:33:44:55")])
    run("scan")
    store = Store(tmp_path / "cli.db")
    assert run("trust", "all") == 0
    assert all(d.trusted for d in store.devices())
    assert run("untrust", "all") == 0
    assert not any(d.trusted for d in store.devices())
    assert "2 devices" in capsys.readouterr().out


def test_commands_without_scanning_need_no_subnet(monkeypatch, capsys):
    monkeypatch.delenv("NETINV_SUBNETS")
    assert run("devices") == 0
    assert "no devices" in capsys.readouterr().out


def test_this_machine_flag_is_shown(monkeypatch, capsys):
    me = host("192.168.1.51", "c4:03:a8:2a:35:14")
    me.details["self"] = True
    use_scanner(monkeypatch, [me])
    run("scan")
    run("devices")
    assert "this-machine" in capsys.readouterr().out


def test_notify_test_without_channels(capsys):
    assert run("notify-test") == 1
    assert "no notification channel" in capsys.readouterr().out


def test_notify_test_reports_each_channel(monkeypatch, capsys):
    from netinv import notify

    class Fake:
        name = "fake"

        def send(self, subject, body, alert):
            if self.broken:
                raise notify.NotifyError("HTTP 401")

        broken = False

    ok, bad = Fake(), Fake()
    bad.broken = True
    monkeypatch.setattr(notify, "build_notifier", lambda settings: notify.Notifier([ok], settings))
    assert run("notify-test") == 0 and "fake: ok" in capsys.readouterr().out
    monkeypatch.setattr(notify, "build_notifier", lambda settings: notify.Notifier([bad], settings))
    assert run("notify-test") == 1 and "FAILED - HTTP 401" in capsys.readouterr().out


def test_run_starts_the_server(monkeypatch):
    import uvicorn

    started = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: started.update(app=app, **kw))
    monkeypatch.setenv("NETINV_ADMIN_TOKEN", "boss")
    assert run("run", "--port", "9999") == 0
    assert started["port"] == 9999 and started["host"] == "127.0.0.1"
    assert started["app"].title == "netinv"


def test_oui_update_explains_certificate_problems(monkeypatch, capsys, tmp_path):
    import ssl
    import urllib.error

    def fail(*a, **k):
        raise urllib.error.URLError(ssl.SSLCertVerificationError("self-signed certificate"))

    monkeypatch.setattr(cli.urllib.request, "urlopen", fail)
    assert run("oui-update") == 2
    err = capsys.readouterr().err
    assert "SSLCertVerificationError" in err and "download the file in your browser" in err
    assert str(tmp_path / "oui.csv") in err


def test_oui_update_reports_network_errors(monkeypatch, capsys):
    import urllib.error

    def fail(*a, **k):
        raise urllib.error.URLError(TimeoutError())

    monkeypatch.setattr(cli.urllib.request, "urlopen", fail)
    assert run("oui-update") == 2
    err = capsys.readouterr().err
    assert "TimeoutError" in err and "browser" not in err


def test_main_reads_the_env_file(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("NETINV_SUBNETS")
    (tmp_path / ".env").write_text("NETINV_SUBNETS=bad-subnet\n")
    assert run("scan") == 2
    assert "not a valid subnet" in capsys.readouterr().err
    monkeypatch.delenv("NETINV_SUBNETS", raising=False)


def test_oui_update_uses_the_ca_bundle(monkeypatch, tmp_path):
    seen = {}

    def fake_context(cafile=None):
        seen["cafile"] = cafile
        return object()

    monkeypatch.setattr(cli.ssl, "create_default_context", fake_context)
    monkeypatch.setenv("NETINV_CA_BUNDLE", str(tmp_path / "corp.pem"))
    assert isinstance(cli._ssl_context(), object) and seen["cafile"] == str(tmp_path / "corp.pem")
    monkeypatch.delenv("NETINV_CA_BUNDLE")
    cli._ssl_context()
    assert seen["cafile"] is None


def test_an_empty_scan_warns(monkeypatch, capsys):
    use_scanner(monkeypatch, [])
    assert run("scan") == 0
    captured = capsys.readouterr()
    assert "no changes" in captured.out and "no device was found" in captured.err

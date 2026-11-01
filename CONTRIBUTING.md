# Contributing

Issues and pull requests are welcome.

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
ruff check .
mypy
pytest --cov
```

CI runs the same on Python 3.11 to 3.14 (and on Windows, because the scanner reads the output of
the system `ping` and `arp`), plus a Docker smoke test.

- **Anything that reads from the network is hostile input:** validate lengths and offsets, cap
  what you keep, never raise on garbage, and add tests with truncated and looping packets.
- **New device information source:** add a function in `probes.py` with a short timeout that
  returns `None` when the device is silent, and test it against a fake UDP server on loopback.
- **System commands are injectable** so the logic can be tested without a network.
- Keep the changelog up to date under a new heading.

# Mini SIEM

A lightweight Security Information and Event Management system for real-time threat detection
and monitoring. It collects system and application logs, normalizes them into one event schema,
runs rule-based detection (brute force, password spraying, port scans, suspicious HTTP, and more),
raises alerts, and shows them on a web dashboard.

Status: under construction. See [PLAN.md](PLAN.md) for the architecture, detection rules and work split.

## Development

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux: source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

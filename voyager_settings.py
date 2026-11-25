"""Shared settings for the web app and the command-line tools.

Stored in data/settings.json next to this file (never committed). Environment variables win:
SPLUNK_BASE, SPLUNK_LOCALE, SPLUNK_APP, VOYAGER_URL.
"""
import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
SETTINGS_PATH = HERE / "data" / "settings.json"

DEFAULTS = {
    "splunk_base": "",          # e.g. https://splunk.example.com (Splunk Web, not the 8089 management port)
    "splunk_locale": "en-US",   # the locale segment in Splunk Web URLs
    "splunk_app": "",           # app context for searches; empty = your default app
    "voyager_url": "http://localhost:8080",
    "max_jobs": 2,              # Splunk searches per module running at once
}
ENV = {"splunk_base": "SPLUNK_BASE", "splunk_locale": "SPLUNK_LOCALE", "splunk_app": "SPLUNK_APP",
       "voyager_url": "VOYAGER_URL"}


def load():
    s = dict(DEFAULTS)
    try:
        s.update({k: v for k, v in json.loads(SETTINGS_PATH.read_text(encoding="utf-8")).items() if k in DEFAULTS})
    except (OSError, ValueError):
        pass
    for k, env in ENV.items():
        if os.environ.get(env):
            s[k] = os.environ[env]
    s["splunk_base"] = (s["splunk_base"] or "").rstrip("/")
    s["splunk_locale"] = (s["splunk_locale"] or "en-US").strip("/")
    return s


def save(values):
    s = load()
    for k, v in values.items():
        if k in DEFAULTS:
            s[k] = int(v) if isinstance(DEFAULTS[k], int) else str(v).strip()
    s["splunk_base"] = s["splunk_base"].rstrip("/")
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = SETTINGS_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(s, indent=2), encoding="utf-8")
    os.replace(tmp, SETTINGS_PATH)
    return s


def get(key):
    return load()[key]


def splunk_url(path):
    """Splunk Web URL for a path such as 'config' or 'splunkd/__raw/services/...'."""
    s = load()
    if not s["splunk_base"]:
        raise RuntimeError("Splunk URL not set: open Settings in Voyager, or set SPLUNK_BASE")
    return f"{s['splunk_base']}/{s['splunk_locale']}/{path.lstrip('/')}"

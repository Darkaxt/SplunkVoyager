"""Shared settings for the web app and the command-line tools.

Stored in data/settings.json next to this file (never committed). Holds one or more Splunk instances, one of
them the default. Environment variables override the default instance: SPLUNK_BASE, SPLUNK_LOCALE, SPLUNK_APP;
and VOYAGER_URL the app's own address.

For code written for a single instance, load() also returns the default instance's values as splunk_base,
splunk_locale and splunk_app. splunk_url() follows the instance selected with use_instance() (per request or
thread), else the default.
"""
import contextlib
import contextvars
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
SETTINGS_PATH = HERE / "data" / "settings.json"

DEFAULTS = {
    "instances": [],            # [{"name", "base", "locale", "app"}]
    "default_instance": "",
    "voyager_url": "http://localhost:8080",
    "max_jobs": 2,              # Splunk searches per module running at once
    "auto_update": "apply",     # apply: install new versions from GitHub and restart | check: only show them | off
    "update_interval": 30,      # minutes between checks
}
INSTANCE_DEFAULTS = {"name": "", "base": "", "locale": "en-US", "app": ""}
_current = contextvars.ContextVar("voyager_splunk_instance", default=None)


def host_of(url_or_host):
    s = (url_or_host or "").strip().lower()
    if "://" in s:
        return (urlsplit(s).hostname or "").lower()
    return s.lstrip(".").split(":")[0].split("/")[0]


def _clean_instance(i):
    i = {**INSTANCE_DEFAULTS, **{k: str(v or "").strip() for k, v in (i or {}).items() if k in INSTANCE_DEFAULTS}}
    u = urlsplit(i["base"])
    if i["base"]:
        if u.scheme not in ("http", "https") or not u.netloc:
            raise ValueError(f"Splunk URL must look like https://splunk.example.com (got {i['base']!r})")
        i["base"] = f"{u.scheme}://{u.netloc}{u.path.rstrip('/')}"
    i["locale"] = (i["locale"] or "en-US").strip("/")
    i["name"] = i["name"] or host_of(i["base"]) or "splunk"
    return i


def load():
    raw = {}
    try:
        raw = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    s = {**DEFAULTS, **{k: v for k, v in raw.items() if k in DEFAULTS}}
    insts = []
    for i in s.get("instances") or []:
        try:
            insts.append(_clean_instance(i))
        except ValueError:
            continue
    if not insts and raw.get("splunk_base"):      # settings written by the single-instance version
        insts.append(_clean_instance({"base": raw["splunk_base"], "locale": raw.get("splunk_locale"),
                                      "app": raw.get("splunk_app")}))
    s["instances"] = insts
    names = [i["name"] for i in insts]
    if s["default_instance"] not in names:
        s["default_instance"] = names[0] if names else ""
    if os.environ.get("VOYAGER_URL"):
        s["voyager_url"] = os.environ["VOYAGER_URL"]
    d = dict(next((i for i in insts if i["name"] == s["default_instance"]), INSTANCE_DEFAULTS))
    if os.environ.get("SPLUNK_BASE"):
        d.update(base=os.environ["SPLUNK_BASE"].rstrip("/"), name=d["name"] or host_of(os.environ["SPLUNK_BASE"]))
    if os.environ.get("SPLUNK_LOCALE"):
        d["locale"] = os.environ["SPLUNK_LOCALE"]
    if os.environ.get("SPLUNK_APP"):
        d["app"] = os.environ["SPLUNK_APP"]
    s["default"] = d
    s["splunk_base"], s["splunk_locale"], s["splunk_app"] = d["base"], d["locale"] or "en-US", d["app"]
    return s


def save(values):
    s = load()
    if "instances" in values:
        insts, seen = [], set()
        for i in values["instances"] or []:
            if not (i or {}).get("base", "").strip():
                continue
            c = _clean_instance(i)
            if c["name"].lower() in seen:
                raise ValueError(f"two instances are named {c['name']!r}")
            seen.add(c["name"].lower())
            insts.append(c)
        s["instances"] = insts
    elif "splunk_base" in values:               # single-instance callers: update the default instance
        c = _clean_instance({"base": values.get("splunk_base"), "locale": values.get("splunk_locale"),
                             "app": values.get("splunk_app"), "name": s["default_instance"]})
        s["instances"] = [c] + [i for i in s["instances"] if i["name"] != c["name"]]
        s["default_instance"] = c["name"]
    if "default_instance" in values:
        s["default_instance"] = str(values["default_instance"] or "")
    if "voyager_url" in values:
        s["voyager_url"] = str(values["voyager_url"]).strip() or DEFAULTS["voyager_url"]
    if "max_jobs" in values:
        s["max_jobs"] = max(1, min(10, int(values["max_jobs"])))
    if "auto_update" in values:
        if values["auto_update"] not in ("apply", "check", "off"):
            raise ValueError("auto_update must be apply, check or off")
        s["auto_update"] = values["auto_update"]
    if "update_interval" in values:
        s["update_interval"] = max(5, min(1440, int(values["update_interval"])))
    names = [i["name"] for i in s["instances"]]
    if s["default_instance"] not in names:
        s["default_instance"] = names[0] if names else ""
    out = {k: s[k] for k in DEFAULTS}
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = SETTINGS_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(out, indent=2), encoding="utf-8")
    os.replace(tmp, SETTINGS_PATH)
    return load()


def get(key):
    return load()[key]


def instance(ref=None):
    """Instance by name, URL or cookie domain (host or parent domain); None/unknown -> the default."""
    s = load()
    if ref:
        r = str(ref).strip().lower()
        for i in s["instances"]:
            if i["name"].lower() == r:
                return i if i["name"] != s["default"]["name"] else s["default"]
        h = host_of(r)
        for i in s["instances"]:
            ih = host_of(i["base"])
            if h and (ih == h or ih.endswith("." + h) or h.endswith("." + ih)):
                return i if i["name"] != s["default"]["name"] else s["default"]
    return s["default"]


@contextlib.contextmanager
def use_instance(ref):
    """splunk_url() inside this block goes to the instance matching ref (name, URL or cookie domain)."""
    tok = _current.set(instance(ref) if ref else None)
    try:
        yield
    finally:
        _current.reset(tok)


def splunk_url(path):
    """Splunk Web URL for a path such as 'config' or 'splunkd/__raw/services/...'."""
    i = _current.get() or load()["default"]
    if not i.get("base"):
        raise RuntimeError("Splunk URL not set: open Settings in Voyager, or set SPLUNK_BASE")
    return f"{i['base']}/{(i.get('locale') or 'en-US').strip('/')}/{path.lstrip('/')}"


def origins():
    """Origins of all configured instances (for the CORS rule and the userscript)."""
    s = load()
    out = []
    for i in s["instances"] + [s["default"]]:
        u = urlsplit(i.get("base") or "")
        if u.scheme and u.netloc:
            o = f"{u.scheme}://{u.netloc}".lower()
            if o not in out:
                out.append(o)
    return out

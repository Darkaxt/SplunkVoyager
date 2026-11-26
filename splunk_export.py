#!/usr/bin/env python3
"""
splunk_export.py - Run heavy Splunk searches and save the results to disk without the
Splunk web UI rendering anything. Built to survive laptop sleep, VPN drops and expired
sessions: every run can be interrupted and resumed.

Authentication (first match wins):
  1. SPLUNK_COOKIE env var  - the Cookie header copied from the browser's dev tools
  2. --cookies FILE         - a cookie JSON or a text file holding a Cookie header
  3. SplunkVoyager's DB     - data/splunkvoyager.db next to this script (or --db PATH),
                              filled by the userscript while SplunkVoyager (run.py) is running
When the session expires mid-run, the script waits and re-reads these sources, so
reloading any Splunk page (with SplunkVoyager running) lets it continue on its own.

Main command: run (resumable, split by time windows)
  python splunk_export.py run "@query.spl" --earliest 2026-11-01 --latest 2026-11-20 \\
         --chunk 1d --app search --out-dir exports\\rps
  - Runs one Splunk job per window (--max-jobs at a time), downloads each window to its
    own file (part-0001 = earliest), and retries windows that fail or come back with
    indexer-peer errors. Add --merge to also get one merged file.
  - Progress lives in exports\\rps\\manifest.json. After any interruption run:
        python splunk_export.py run --out-dir exports\\rps
    Jobs keep running on Splunk while the laptop sleeps and are picked up again.
  - Times: YYYY-MM-DD, YYYY-MM-DDTHH:MM[:SS] (laptop's local time), epoch seconds,
    now, or relative like -7d, -12h, -7d@d, -2h@h.

Other commands
  sid <SID|URL> -o FILE     download results of an existing job (--resume to continue)
  search <SPL> -o FILE      one job, no windows (simple cases)
  status|touch <SID>        inspect a job / extend its lifetime
  delete <SID|URL> [...]    remove jobs, even stuck ones (tries DELETE, cancel, then a 5s lifetime)
"""
import argparse
import csv
import io
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse, parse_qs, quote

import requests

HERE = Path(__file__).resolve().parent
try:  # shared with the Voyager web app (data/settings.json); environment variables win there too
    sys.path.insert(0, str(HERE))
    import voyager_settings as _vs
    SETTINGS = _vs.load()
except Exception:
    SETTINGS = {"splunk_base": os.environ.get("SPLUNK_BASE", ""), "splunk_locale": os.environ.get("SPLUNK_LOCALE", "en-US"),
                "splunk_app": os.environ.get("SPLUNK_APP", ""), "voyager_url": os.environ.get("VOYAGER_URL", "http://localhost:8080")}
DEFAULT_BASE = SETTINGS["splunk_base"]
DEFAULT_LOCALE = SETTINGS["splunk_locale"]
PAGE_SIZE = 50000  # Splunk's default [restapi] maxresultrows; larger pages get truncated server-side


def log(msg=""):
    print(f"[{datetime.now():%H:%M:%S}] {msg}", file=sys.stderr, flush=True)


class AuthError(Exception):
    pass


class JobGone(Exception):
    pass


# --------------------------------------------------------------------------- auth
def cookies_from_db(db_path, host, quiet=False):
    """Cookies of the most recently checked active session in SplunkVoyager's SQLite DB."""
    import sqlite3
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        row = con.execute(
            "SELECT id, username FROM sessions WHERE lower(domain)=? AND is_active=1 "
            "ORDER BY last_check DESC, id DESC LIMIT 1", (host.lower(),)).fetchone()
        if not row:
            return None
        pairs = con.execute("SELECT cookie_name, cookie_value FROM cookies WHERE session_id=? ORDER BY id",
                            (row[0],)).fetchall()
    finally:
        con.close()
    if not pairs:
        return None
    if not quiet:
        log(f"Using cookies of SplunkVoyager session {row[0]} ({row[1]}) from {db_path}")
    return "; ".join(f"{k}={v}" for k, v in pairs)


def find_cookies(path_or_none, db_or_none, host, quiet=False):
    """Return a Cookie header string, or None if no source has one."""
    env = os.environ.get("SPLUNK_COOKIE")
    if env:
        return env.strip()

    if path_or_none:
        p = Path(path_or_none)
        if not p.is_file():
            sys.exit(f"Cookie file not found: {p}")
        text = p.read_text(encoding="utf-8").strip()
        if not text.startswith("{"):
            return text  # plain "a=b; c=d" header saved to a file
        data = json.loads(text)
        cookies = data.get("cookies", data)
        return "; ".join(f"{k}={v.get('value') if isinstance(v, dict) else v}" for k, v in cookies.items())

    db = Path(db_or_none) if db_or_none else HERE / "data" / "splunkvoyager.db"
    if db.is_file():
        header = cookies_from_db(db, host, quiet)
        if header:
            return header
    elif db_or_none:
        sys.exit(f"Database not found: {db}")

    legacy = HERE / "data" / "cookies" / f"{host}_latest.json"
    if legacy.is_file():
        return find_cookies(str(legacy), None, host, quiet)
    return None


def csrf_from_header(cookie_header):
    m = re.search(r"(?:^|;\s*)splunkweb_csrf_token_\d+=([^;]+)", cookie_header)
    return m.group(1) if m else None


# --------------------------------------------------------------------------- Splunk client
class Splunk:
    def __init__(self, base, locale, cookie_source, verify=True, timeout=300):
        self.base = base.rstrip("/")
        self.locale = locale
        self.root = f"{self.base}/{locale}/splunkd/__raw"
        self.cookie_source = cookie_source  # callable(quiet) -> header or None
        self.timeout = timeout
        self.s = requests.Session()
        self.s.verify = verify
        self.s.headers.update({"X-Requested-With": "XMLHttpRequest", "Accept": "*/*"})
        self.user = None
        self.default_app = None
        header = cookie_source(False)
        if not header:
            sys.exit("No cookies found. Start SplunkVoyager (run.py) and reload a Splunk page with the "
                     "userscript, or pass --db / --cookies, or set SPLUNK_COOKIE to the Cookie header copied "
                     "from your browser's dev tools.")
        self._apply(header)

    def _apply(self, header):
        self.cookie_header = header
        self.s.headers["Cookie"] = header
        token = csrf_from_header(header)
        if token:
            self.s.headers["X-Splunk-Form-Key"] = token
        else:
            self.s.headers.pop("X-Splunk-Form-Key", None)

    def _req(self, method, url, **kw):
        kw.setdefault("timeout", self.timeout)
        r = self.s.request(method, url, **kw)
        if r.status_code in (401, 403) or "/account/login" in r.url:
            raise AuthError(f"HTTP {r.status_code}")
        return r

    # -- session
    def whoami(self):
        r = self._req("GET", f"{self.base}/{self.locale}/config", timeout=60)
        try:
            d = r.json()
        except ValueError:
            raise AuthError("got a login page instead of /config")
        user = d.get("USERNAME")
        if not user or user.lower() == "unknown":
            raise AuthError("session user is 'unknown'")
        self.user, self.default_app = user, d.get("DEFAULT_NAMESPACE", "search")
        # /config is answered by splunkweb alone; job calls go through to splunkd, whose session can expire
        # while the web one still looks fine. Check splunkd too, so "session OK" means jobs work.
        r = self._req("GET", f"{self.root}/services/authentication/current-context",
                      params={"output_mode": "json"}, timeout=60)
        if r.status_code >= 400:
            raise AuthError(f"splunkd answered HTTP {r.status_code} (web session OK, splunkd session not)")
        self._last_ok = time.time()
        return self.user, self.default_app

    def reauth_wait(self, reason):
        """Block until a working session is available again (cookies refreshed in DB/env)."""
        log(f"Splunk session not usable ({reason}).")
        log("  -> Reload any Splunk page in your browser (SplunkVoyager running), or refresh SPLUNK_COOKIE "
            "and restart. Waiting; checking every 30s...")
        last_header, last_note, last_ask = None, time.time(), 0
        if time.time() - getattr(self, "_last_ok", 0) < 60:
            # the check passed a moment ago but the next call failed again: don't spin, wait first
            time.sleep(30)
        while True:
            if time.time() - last_ask > 120:
                self.ask_browser_refresh(reason)
                last_ask = time.time()
            header = self.cookie_source(True)
            if header and header != last_header:
                last_header = header
                self._apply(header)
                try:
                    self.whoami()
                    log(f"Session OK again as {self.user}. Continuing.")
                    return
                except AuthError:
                    pass
                except requests.exceptions.RequestException as e:
                    log(f"  network not ready yet: {type(e).__name__}")
                    last_header = None
            elif header:
                # same cookies: maybe the network was the problem, retry them
                try:
                    self.whoami()
                    log(f"Session OK again as {self.user}. Continuing.")
                    return
                except (AuthError, requests.exceptions.RequestException):
                    pass
            if time.time() - last_note > 600:
                log("  still waiting for a fresh Splunk session...")
                last_note = time.time()
            time.sleep(30)

    def ask_browser_refresh(self, reason):
        """Ask SplunkVoyager to reload the keep-alive Splunk tab (fresh SSO session -> fresh cookies in the DB)."""
        url = SETTINGS["voyager_url"].rstrip("/") + "/api/request_refresh"
        try:
            requests.post(url, json={"reason": reason}, timeout=5, proxies={"http": None, "https": None})
            if not getattr(self, "_told_refresh", False):
                log("  -> asked SplunkVoyager to reload the keep-alive tab (a Splunk tab opened once with #voyager)")
                self._told_refresh = True
        except requests.exceptions.RequestException:
            pass  # SplunkVoyager not running: reload a Splunk page by hand

    # -- jobs
    def job(self, sid):
        r = self._req("GET", f"{self.root}/services/search/jobs/{quote(sid, safe='')}",
                      params={"output_mode": "json"})
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()["entry"][0]["content"]

    def control(self, sid, action, **extra):
        r = self._req("POST", f"{self.root}/services/search/jobs/{quote(sid, safe='')}/control",
                      data={"action": action, "output_mode": "json", **extra}, timeout=60)
        return r.status_code < 300, r.text[:300]

    def delete_job(self, sid, verify_minutes=10):
        """Remove a job, trying progressively blunter methods. Returns True once it is gone."""
        url = f"{self.root}/services/search/jobs/{quote(sid, safe='')}"
        steps = [
            ("DELETE the job", lambda: self._req("DELETE", url, params={"output_mode": "json"})),
            ("cancel the job", lambda: self._req("POST", f"{url}/control",
                                                 data={"action": "cancel", "output_mode": "json"})),
            ("set its lifetime to 5s so Splunk's reaper removes it",
             lambda: self._req("POST", f"{url}/control",
                               data={"action": "setttl", "ttl": "5", "output_mode": "json"})),
        ]
        for label, call in steps:
            log(f"  trying to {label} (big jobs can take minutes to answer)...")
            t = time.time()
            try:
                r = call()
            except requests.exceptions.Timeout:
                log(f"    no answer after {time.time() - t:.0f}s")
                continue
            if r.status_code == 404:
                log("    Splunk says the job no longer exists")
                return True
            if r.status_code >= 300:
                log(f"    refused: HTTP {r.status_code} {r.text[:200]}")
                continue
            log(f"    accepted after {time.time() - t:.0f}s. Checking it is really gone, for up to "
                f"{verify_minutes} min (Ctrl+C is safe: Splunk already accepted the request)...")
            start = time.time()
            deadline = start + verify_minutes * 60
            check = 0
            while time.time() < deadline:
                check += 1
                t = time.time()
                try:
                    c = self.job(sid)
                except requests.exceptions.Timeout:
                    log(f"    check {check}: no answer after {time.time() - t:.0f}s")
                    c = "timeout"
                if c is None:
                    log(f"    check {check}: job no longer exists ({time.time() - start:.0f}s after the request)")
                    return True
                if c != "timeout":
                    log(f"    check {check} ({time.time() - t:.0f}s to answer): still listed, "
                        f"state={c.get('dispatchState')}; Splunk is probably still removing its data")
                time.sleep(15)
            log(f"    still listed after {verify_minutes} min; trying the next method")
        return False

    def create(self, app, query, earliest, latest, ttl, max_time=0, level="fast"):
        q = query.strip()
        if not q.startswith("|") and not q.lower().startswith("search "):
            q = "search " + q
        params = {
            "output_mode": "json",
            "search": q,
            "earliest_time": str(earliest),
            "latest_time": str(latest),
            "exec_mode": "normal",
            # Lightweight settings: no timeline buckets, no field discovery, no preview.
            "status_buckets": "0",
            "adhoc_search_level": level,
            "preview": "0",
            "auto_cancel": "0",
            "auto_pause": "0",
            "timeout": str(ttl),
            "max_time": str(max_time),
            "ui_dispatch_app": app,
            "provenance": "UI:Search",
        }
        url = f"{self.root}/servicesNS/{quote(self.user, safe='')}/{quote(app, safe='')}/search/v2/jobs"
        r = self._req("POST", url, data=params, timeout=120)
        if r.status_code == 400:
            msgs = r.text
            try:
                msgs = "; ".join(m.get("text", "") for m in r.json().get("messages", [])) or r.text
            except ValueError:
                pass
            sys.exit(f"Splunk rejected the search (HTTP 400): {msgs[:600]}\nFix the query and run again.")
        if r.status_code >= 300:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:400]}")
        return r.json()["sid"]

    def results_page(self, sid, app, offset, count, fmt, endpoint):
        url = (f"{self.root}/servicesNS/nobody/{quote(app, safe='')}/search/v2/jobs/"
               f"{quote(sid, safe='')}/{endpoint}")
        r = self._req("GET", url, params={"output_mode": fmt, "offset": offset, "count": count})
        if r.status_code == 404:
            raise JobGone(sid)
        if r.status_code == 204:
            return None
        r.raise_for_status()
        return r


# --------------------------------------------------------------------------- job helpers
def parse_sid(arg):
    """Accept a bare SID or a Splunk search URL; return (sid, app_from_url_or_None)."""
    if arg.startswith("http"):
        u = urlparse(arg)
        sid = parse_qs(u.query).get("sid", [None])[0]
        if not sid:
            sys.exit("No sid= parameter found in that URL.")
        m = re.search(r"/app/([^/]+)/", u.path)
        return sid, (m.group(1) if m else None)
    return arg, None


def fmt_status(c):
    return (f"state={c.get('dispatchState')} progress={float(c.get('doneProgress', 0)) * 100:.1f}% "
            f"scanned={int(c.get('scanCount', 0)):,} events={int(c.get('eventCount', 0)):,} "
            f"results={int(c.get('resultCount', 0)):,} run={float(c.get('runDuration', 0)):.0f}s")


def job_messages(c):
    """Splunk returns messages either as [{"type": ..., "text": ...}] or {"level": [texts]}."""
    msgs = c.get("messages") or []
    out = []
    if isinstance(msgs, dict):
        for level, items in msgs.items():
            for m in (items if isinstance(items, list) else [items]):
                out.append((str(level).upper(), str(m)))
    elif isinstance(msgs, list):
        for m in msgs:
            if isinstance(m, dict):
                out.append((str(m.get("type", "MSG")).upper(), str(m.get("text", json.dumps(m)))))
            else:
                out.append(("MSG", str(m)))
    return out


INCOMPLETE_PATTERNS = re.compile(
    r"might be incomplete|timed out waiting|connection (reset|closed)|reading error|"
    r"unable to distribute|search process did not exit cleanly|peer", re.I)


def incomplete_reasons(c):
    """Error messages meaning the job's data is partial (indexer peers dropped out etc.)."""
    return [t for lvl, t in job_messages(c) if lvl in ("ERROR", "FATAL") and INCOMPLETE_PATTERNS.search(t)]


def truncation_warnings(c):
    return [t for _, t in job_messages(c) if re.search(r"subsearch.*(truncat|maxout)", t, re.I)]


def describe_done(c):
    flags = [k for k in ("isFinalized", "isZombie", "isSaved", "isPaused", "isFailed") if c.get(k)]
    log(f"Job done. flags={','.join(flags) or 'none'} reportSearch={'yes' if c.get('reportSearch') else 'no'} "
        f"diskUsage={int(c.get('diskUsage', 0)) / 1e6:,.1f} MB")
    for level, text in job_messages(c):
        log(f"  Splunk {level}: {text}")


# --------------------------------------------------------------------------- download
def count_records(path, fmt):
    if not Path(path).exists():
        return 0
    if fmt == "jsonl":
        with open(path, "rb") as f:
            return sum(1 for line in f if line.strip())
    with open(path, encoding="utf-8", newline="") as f:
        return max(sum(1 for _ in csv.reader(f)) - 1, 0)


def write_page(resp, fh, fmt, first):
    """Write one page (already fully received) to the open text file; return record count."""
    if fmt == "csv":
        # Parsed as CSV, not lines, so multi-line field values are kept intact and counted correctly.
        reader = csv.reader(io.StringIO(resp.content.decode("utf-8-sig"), newline=""))
        try:
            header = next(reader)
        except StopIteration:
            return 0
        rows = list(reader)
        w = csv.writer(fh)
        if first:
            w.writerow(header)
        w.writerows(rows)
        return len(rows)
    rows = resp.json().get("results", [])
    fh.write("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows))
    return len(rows)


def page_has_rows(resp, fmt):
    if fmt == "csv":
        return len([l for l in resp.content.splitlines() if l.strip()]) >= 2  # header + a row
    try:
        return bool(resp.json().get("results"))
    except ValueError:
        return False


def download_job(sp, sid, app, content, out, fmt, page_size, start_offset=0, quiet=False):
    """Page through a finished job until an empty page. Returns records written in total.
    Job counts are only a hint: they can be 0 on odd jobs while data still exists."""
    out = Path(out)
    counts = {"results": int(content.get("resultCount", 0)), "events": int(content.get("eventCount", 0))}
    order = ["results", "events"] if content.get("reportSearch") or counts["results"] else ["events", "results"]
    api_fmt = {"csv": "csv", "jsonl": "json"}[fmt]

    endpoint = None
    for ep in order:
        try:
            r = sp.results_page(sid, app, start_offset, 1, api_fmt, ep)
        except JobGone:
            if ep == order[-1] and endpoint is None:
                raise
            continue
        if r is not None and page_has_rows(r, fmt):
            endpoint = ep
            break
    if endpoint is None:
        if start_offset == 0:
            out.write_text("", encoding="utf-8")
        return start_offset

    total = counts[endpoint] or None
    offset = start_offset
    t0 = time.time()
    with open(out, "a" if start_offset else "w", encoding="utf-8", newline="") as fh:
        while total is None or offset < total:
            n = page_size if total is None else min(page_size, total - offset)
            r = sp.results_page(sid, app, offset, n, api_fmt, endpoint)
            got = 0 if r is None else write_page(r, fh, fmt, first=(offset == 0))
            fh.flush()
            if got == 0:
                break
            offset += got
            if not quiet or total is None or total > page_size:
                rate = (offset - start_offset) / max(time.time() - t0, 1e-6)
                log(f"    {offset:,}/{f'{total:,}' if total else '?'} records ({rate:,.0f}/s)")
    return offset


# --------------------------------------------------------------------------- time windows
REL = re.compile(r"^-(\d+)([smhdw])(?:@([smhdw]))?$")
UNIT_S = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def snap(dt, unit):
    if unit == "s":
        return dt.replace(microsecond=0)
    if unit == "m":
        return dt.replace(second=0, microsecond=0)
    if unit == "h":
        return dt.replace(minute=0, second=0, microsecond=0)
    d = dt.replace(hour=0, minute=0, second=0, microsecond=0)
    if unit == "w":
        d -= timedelta(days=(d.weekday() + 1) % 7)  # Splunk @w = Sunday
    return d


def parse_time(s, now=None):
    """Return epoch seconds (int) for an absolute or simple relative time spec (local time)."""
    now = now or datetime.now()
    s = str(s).strip()
    if s == "now":
        return int(now.timestamp())
    if re.fullmatch(r"\d{9,11}(\.\d+)?", s):
        return int(float(s))
    m = REL.match(s)
    if m:
        dt = now - timedelta(seconds=int(m.group(1)) * UNIT_S[m.group(2)])
        if m.group(3):
            dt = snap(dt, m.group(3))
        return int(dt.timestamp())
    for f in ("%Y-%m-%d", "%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"):
        try:
            return int(datetime.strptime(s, f).timestamp())
        except ValueError:
            pass
    sys.exit(f"Can't parse time '{s}'. Use YYYY-MM-DD[THH:MM[:SS]], epoch, now, or -7d / -12h@h.")


def parse_chunk(s):
    m = re.fullmatch(r"(\d+)([mhdw])", s.strip())
    if not m:
        sys.exit(f"Bad --chunk '{s}'. Examples: 30m, 6h, 1d, 1w")
    return int(m.group(1)) * UNIT_S[m.group(2)]


def ts(epoch):
    return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M")


# --------------------------------------------------------------------------- manifest
class Manifest:
    """Progress state of a `run`, saved atomically after every change."""

    def __init__(self, out_dir):
        self.dir = Path(out_dir)
        self.path = self.dir / "manifest.json"
        self.data = None

    def exists(self):
        return self.path.is_file()

    def load(self):
        tmp = self.path.with_suffix(".json.tmp")
        if tmp.is_file() and (not self.path.is_file() or tmp.stat().st_mtime > self.path.stat().st_mtime):
            try:  # a save that could not replace manifest.json (file locked) left newer progress here
                self.data = json.loads(tmp.read_text(encoding="utf-8"))
                return self.data
            except (ValueError, OSError):
                pass
        self.data = json.loads(self.path.read_text(encoding="utf-8"))
        return self.data

    def save(self):
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
        # Windows: antivirus / indexer / an open editor can hold manifest.json for a moment -> retry
        for i in range(40):
            try:
                os.replace(tmp, self.path)
                return
            except PermissionError:
                time.sleep(0.25 if i < 20 else 1)
        try:  # still locked: write in place rather than crash (tmp keeps a full copy)
            self.path.write_text(tmp.read_text(encoding="utf-8"), encoding="utf-8")
        except PermissionError as e:
            log(f"WARNING: could not update {self.path} ({e}); progress is in {tmp.name}, will retry next save")

    @property
    def windows(self):
        return self.data["windows"]


# window states: pending -> running -> downloading -> done   (or failed after max attempts)
TERMINAL = ("done", "failed")


def mask_text(text, masks):
    """Replace secret strings (longest first) by <SECRET> before anything is written to disk."""
    for m in sorted((m for m in masks or [] if m), key=len, reverse=True):
        text = text.replace(m, "<SECRET>")
    return text


def query_hash(q):
    import hashlib
    return hashlib.sha256(q.strip().encode("utf-8")).hexdigest()


def plan(args, sp):
    q = args.query
    if q.startswith("@"):
        q = Path(q[1:]).read_text(encoding="utf-8")
    explicit = getattr(args, "windows", None)   # [(epoch_start, epoch_end), ...] from a caller that knows where data is
    if explicit:
        earliest, latest = int(min(w[0] for w in explicit)), int(max(w[1] for w in explicit))
        ranges = sorted((int(a), int(b)) for a, b in explicit)
    else:
        earliest, latest = parse_time(args.earliest), parse_time(args.latest)
        ranges = [(earliest, latest)]
    if latest <= earliest:
        sys.exit("--latest must be after --earliest")
    windows, i = [], 1
    for lo, hi in ranges:
        step = parse_chunk(args.chunk) if args.chunk else hi - lo
        t = lo
        while t < hi:
            end = min(t + step, hi)
            windows.append({"n": i, "earliest": t, "latest": end, "state": "pending", "sid": None,
                            "attempts": 0, "records": 0, "file": None, "notes": []})
            t, i = end, i + 1
    fmt = args.format or "jsonl"
    return {
        "version": 1,
        "created": datetime.now().isoformat(timespec="seconds"),
        "query": mask_text(q, getattr(args, "mask", None)),
        "query_sha256": query_hash(q),
        "masked": bool(getattr(args, "mask", None)),
        "app": args.app or SETTINGS.get("splunk_app") or sp.default_app,
        "earliest": earliest, "latest": latest, "chunk": args.chunk,
        "format": fmt,
        "search_level": args.search_level or "fast",
        "windows": windows,
    }


def keep_awake(on):
    """Windows: stop idle sleep while a run is active (closing the lid or a forced policy still wins)."""
    if os.name != "nt":
        return
    try:
        import ctypes
        ES_CONTINUOUS, ES_SYSTEM_REQUIRED = 0x80000000, 0x00000001
        ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS | (ES_SYSTEM_REQUIRED if on else 0))
    except Exception as e:
        log(f"(could not change sleep setting: {e})")


def run(args, sp):
    keep_awake(True)
    try:
        return _run(args, sp)
    finally:
        keep_awake(False)


def _run(args, sp):
    man = Manifest(args.out_dir)
    if man.exists():
        man.load()
        if man.data.get("masked") and not args.query:
            sys.exit(f"{man.path} hides a secret in its query; resume it with the tool that started it "
                     f"(it supplies the query again).")
        if args.query and args.query != "@":
            q = Path(args.query[1:]).read_text(encoding="utf-8") if args.query.startswith("@") else args.query
            same = (query_hash(q) == man.data["query_sha256"]) if man.data.get("query_sha256") \
                else (q.strip() == man.data["query"].strip())
            if not same:
                sys.exit(f"{man.path} belongs to a different query. Use another --out-dir, or omit the "
                         f"query to resume the existing run.")
        log(f"Resuming run in {man.dir} ({len(man.windows)} windows)")
    else:
        if not args.query or not args.earliest or not args.latest:
            sys.exit(f"No manifest in {man.dir}. To start a run give the query, --earliest and --latest.")
        man.data = plan(args, sp)
        if len(man.windows) > 1 and "[" in man.data["query"]:
            sub_has_time = re.search(r"\[[^\]]*\bearliest\s*=", man.data["query"], re.S)
            if not sub_has_time:
                log("WARNING: the query has a subsearch [ ... ] without its own earliest=/latest=. With "
                    "--chunk, it runs over each window's time range only, not the whole period. If it "
                    "should cover the whole period, add earliest=/latest= inside the brackets.")
        man.save()
        log(f"Planned {len(man.windows)} window(s) of {args.chunk or 'whole range'} "
            f"from {ts(man.data['earliest'])} to {ts(man.data['latest'])} -> {man.dir}")

    d = man.data
    app, fmt = d["app"], d["format"]
    real_query = d["query"]
    if args.query and args.query != "@":
        real_query = Path(args.query[1:]).read_text(encoding="utf-8") if args.query.startswith("@") else args.query
    ext = "csv" if fmt == "csv" else "jsonl"
    # A window caught mid-download last time is simply downloaded again.
    for w in man.windows:
        if w["state"] == "downloading":
            w["state"] = "running"
    man.save()

    warned_trunc = set(n for w in man.windows for n in w.get("notes", []) if "subsearch" in n.lower())
    last_status = 0
    next_submit, refused_logged = 0, False
    while True:
        try:
            for w in man.windows:  # a download interrupted by auth/network errors is redone
                if w["state"] == "downloading":
                    w["state"] = "running"
            active = [w for w in man.windows if w["state"] == "running"]
            pending = [w for w in man.windows if w["state"] == "pending"]
            if not active and not pending:
                break

            # 1) submit new jobs up to the concurrency limit
            for w in (pending[: max(0, args.max_jobs - len(active))] if time.time() >= next_submit else []):
                w["attempts"] += 1
                try:
                    w["sid"] = sp.create(app, real_query, w["earliest"], w["latest"], args.job_ttl,
                                         level=d.get("search_level", "fast"))
                    refused_logged = False
                except RuntimeError as e:
                    w["attempts"] -= 1
                    if not refused_logged:
                        log(f"Splunk refused to start window {w['n']} ({str(e)[:200]}). Probably your concurrent "
                            f"search quota: waiting for running jobs to finish, retrying every 30s.")
                        refused_logged = True
                    next_submit = time.time() + 30
                    break
                w["state"] = "running"
                w["submitted"] = datetime.now().isoformat(timespec="seconds")
                man.save()
                log(f"Window {w['n']}/{len(man.windows)} [{ts(w['earliest'])} -> {ts(w['latest'])}] "
                    f"started, attempt {w['attempts']}, SID {w['sid']}")

            # 2) check running jobs
            for w in [w for w in man.windows if w["state"] == "running"]:
                c = sp.job(w["sid"])
                if c is None:
                    log(f"Window {w['n']}: job {w['sid']} expired on Splunk; restarting it")
                    retry_or_fail(w, args, "job expired before download")
                    man.save()
                    continue
                sp.control(w["sid"], "setttl", ttl=str(args.job_ttl))  # keep alive across laptop sleep
                if c.get("isFailed") or c.get("dispatchState") == "FAILED":
                    msg = "; ".join(t for _, t in job_messages(c))[:300]
                    log(f"Window {w['n']}: job FAILED: {msg}")
                    retry_or_fail(w, args, f"failed: {msg}")
                    man.save()
                    continue
                if not c.get("isDone"):
                    continue
                bad = incomplete_reasons(c)
                if bad and not args.accept_incomplete:
                    log(f"Window {w['n']}: finished with indexer errors (data may be partial): {bad[0][:160]}")
                    sp.control(w["sid"], "cancel")
                    retry_or_fail(w, args, f"incomplete: {bad[0][:200]}")
                    man.save()
                    continue
                for t in truncation_warnings(c):
                    if t not in warned_trunc:
                        warned_trunc.add(t)
                        log(f"WARNING window {w['n']}: {t}  -> results of this window are incomplete; "
                            f"use smaller --chunk or replace the subsearch with a lookup.")
                    w["notes"].append(t)
                # 3) download
                w["state"] = "downloading"
                w["file"] = f"part-{w['n']:04d}.{ext}"
                man.save()
                log(f"Window {w['n']}: done ({int(c.get('resultCount', 0)):,} results), downloading...")
                w["records"] = download_job(sp, w["sid"], app, c, man.dir / w["file"], fmt, args.page_size,
                                            quiet=True)
                w["state"] = "done"
                w["finished"] = datetime.now().isoformat(timespec="seconds")
                man.save()
                next_submit = 0  # a slot on Splunk is free again
                log(f"Window {w['n']}: saved {w['records']:,} records to {w['file']}")
                if not args.keep_jobs:
                    sp.control(w["sid"], "cancel")  # free disk quota on Splunk

            if time.time() - last_status > 60:
                summarize(man, sp)
                last_status = time.time()
            time.sleep(args.poll)

        except AuthError as e:
            man.save()
            sp.reauth_wait(str(e))
        except JobGone as e:
            for w in man.windows:
                if w["sid"] == str(e) and w["state"] in ("running", "downloading"):
                    log(f"Window {w['n']}: job vanished during download; restarting it")
                    retry_or_fail(w, args, "job vanished during download")
            man.save()
        except requests.exceptions.RequestException as e:
            man.save()
            log(f"Network problem ({type(e).__name__}); laptop asleep or VPN down? Retrying in 30s...")
            time.sleep(30)

    summarize(man, sp, final=True)
    failed = [w for w in man.windows if w["state"] == "failed"]
    if failed:
        log(f"{len(failed)} window(s) failed after {args.max_attempts} attempts. Fix the cause and rerun with "
            f"--retry-failed to try them again. Not merging yet.")
        sys.exit(2)
    if args.merge:
        merge(man, fmt)
    files = [w["file"] for w in sorted(man.windows, key=lambda w: w["earliest"]) if w["file"]]
    if files and not getattr(args, "no_pack", False):
        try:
            import exportfiles
            exportfiles.pack(man.dir, log)
        except Exception as e:      # never lose a finished run over packing: the part files stay
            log(f"Could not pack the part files ({e}); they stay as they are")
    if files and not args.merge:
        log(f"Results are in {man.dir} ({files[0]} = earliest window"
            f"{', inside export.zip' if (man.dir / 'export.zip').exists() else ''}). Add --merge for a single file.")


def retry_or_fail(w, args, why):
    w["notes"].append(why)
    if w["attempts"] >= args.max_attempts:
        w["state"] = "failed"
        log(f"Window {w['n']}: giving up after {w['attempts']} attempts")
    else:
        w["state"] = "pending"
    w["sid"] = None


def summarize(man, sp, final=False):
    ws = man.windows
    by = {}
    for w in ws:
        by[w["state"]] = by.get(w["state"], 0) + 1
    recs = sum(w["records"] for w in ws if w["state"] == "done")
    parts = ", ".join(f"{k}={v}" for k, v in sorted(by.items()))
    log(f"{'FINISHED' if final else 'Progress'}: {parts} | {recs:,} records saved")
    if not final:
        for w in ws:
            if w["state"] == "running" and w["sid"]:
                try:
                    c = sp.job(w["sid"])
                    if c:
                        log(f"    window {w['n']}: {fmt_status(c)}")
                except (AuthError, requests.exceptions.RequestException):
                    raise
                except Exception:
                    pass


def merge(man, fmt):
    ext = "csv" if fmt == "csv" else "jsonl"
    out = man.dir / f"merged.{ext}"
    total, header_written = 0, False
    with open(out, "w", encoding="utf-8", newline="") as fo:
        import exportfiles
        avail = {pt.name: pt for pt in exportfiles.parts(man.dir, ext)}
        for w in sorted(man.windows, key=lambda w: w["earliest"]):
            pt = avail.get(w["file"] or "")
            if pt is None:
                continue
            if fmt == "csv":
                with pt.open(newline="") as fi:
                    r = csv.reader(fi)
                    hdr = next(r, None)
                    if hdr is None:
                        continue
                    wr = csv.writer(fo)
                    if not header_written:
                        wr.writerow(hdr)
                        header_written = True
                        first_hdr = hdr
                    elif hdr != first_hdr:
                        log(f"WARNING: {w['file']} has different columns than the first file; "
                            f"merged.csv columns may not line up (use jsonl to avoid this).")
                    for row in r:
                        wr.writerow(row)
                        total += 1
            else:
                with pt.open() as fi:
                    for line in fi:
                        if line.strip():
                            fo.write(line if line.endswith("\n") else line + "\n")
                            total += 1
    man.data["merged"] = {"file": out.name, "records": total, "at": datetime.now().isoformat(timespec="seconds")}
    man.save()
    log(f"Merged {total:,} records into {out}")


# --------------------------------------------------------------------------- simple commands
def wait_done(sp, sid, poll, keepalive_ttl):
    log(f"Looking up job {sid} (big jobs can take a minute or more to answer)...")
    while True:
        t = time.time()
        c = sp.job(sid)
        if time.time() - t > 5:
            log(f"  (Splunk took {time.time() - t:.0f}s to answer the status request)")
        if c is None:
            sys.exit(f"Job {sid} not found (404): it expired or belongs to another user/app.")
        log("  " + fmt_status(c))
        if c.get("isFailed") or c.get("dispatchState") == "FAILED":
            describe_done(c)
            sys.exit("Job failed.")
        if c.get("isDone"):
            describe_done(c)
            return c
        sp.control(sid, "setttl", ttl=str(keepalive_ttl))
        time.sleep(poll)


def cmd_single(args, sp, sid, app, resume):
    out = Path(args.out)
    fmt = args.format or ("jsonl" if str(out).endswith((".jsonl", ".json")) else "csv")
    while True:
        try:
            c = wait_done(sp, sid, args.poll, args.job_ttl)
            start = count_records(out, fmt) if resume and out.exists() else 0
            if start:
                log(f"Resuming at record {start:,}")
            n = download_job(sp, sid, app, c, out, fmt, args.page_size, start_offset=start)
            if n == 0:
                log("No data could be retrieved from this job (it is empty or its results were lost).")
            else:
                log(f"Wrote {n:,} records to {out}")
            return
        except AuthError as e:
            sp.reauth_wait(str(e))
            resume = True
        except JobGone:
            sys.exit(f"Job {sid} expired during download. Rerun the search (use `run` for resumable exports).")
        except requests.exceptions.RequestException as e:
            log(f"Network problem ({type(e).__name__}); retrying in 30s...")
            time.sleep(30)
            resume = True


# --------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default=DEFAULT_BASE, help="Splunk Web URL (default: Voyager settings / SPLUNK_BASE)")
    ap.add_argument("--locale", default=DEFAULT_LOCALE)
    ap.add_argument("--db", help="SplunkVoyager database (default: data\\splunkvoyager.db next to this script)")
    ap.add_argument("--cookies", help="cookie JSON from SplunkVoyager, or a text file with a raw Cookie header")
    ap.add_argument("--timeout", type=int, default=300, help="seconds to wait for any single Splunk reply")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (corporate MITM proxies)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("-f", "--format", choices=["csv", "jsonl"], default=None)
        p.add_argument("--page-size", type=int, default=PAGE_SIZE)
        p.add_argument("--poll", type=int, default=15, help="seconds between status checks")
        p.add_argument("--job-ttl", type=int, default=3 * 86400,
                       help="lifetime (s) kept on Splunk jobs so they survive laptop sleep (default 3 days)")
        p.add_argument("--app", help="app context (default: from URL, else your default app)")
        p.add_argument("--search-level", choices=["fast", "smart", "verbose"], default=None,
                       help="Splunk search mode. fast (default) skips field discovery; use smart or "
                            "verbose when exporting raw events and you want all extracted fields")

    p = sub.add_parser("run", help="resumable export split into time windows (recommended)")
    p.add_argument("query", nargs="?", help="SPL, or @file.spl. Omit to resume the run in --out-dir")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--earliest")
    p.add_argument("--latest", default=None)
    p.add_argument("--chunk", help="window size, e.g. 30m, 6h, 1d (default: whole range as one window)")
    p.add_argument("--max-jobs", type=int, default=2, help="windows running at once on Splunk (default 2)")
    p.add_argument("--max-attempts", type=int, default=4)
    p.add_argument("--accept-incomplete", action="store_true",
                   help="keep windows that finished with indexer-peer errors instead of rerunning them")
    p.add_argument("--retry-failed", action="store_true", help="give failed windows another set of attempts")
    p.add_argument("--keep-jobs", action="store_true", help="don't delete finished jobs from Splunk")
    p.add_argument("--no-pack", action="store_true",
                   help="keep one part file per window instead of packing them into export.zip when the run completes")
    p.add_argument("--merge", action="store_true",
                   help="also write all windows into one merged file at the end (off by default)")
    common(p)

    p = sub.add_parser("sid", help="download results of an existing job")
    p.add_argument("sid", help="SID or full Splunk search URL containing ?sid=")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--resume", action="store_true", help="append to an existing partial output file")
    common(p)

    p = sub.add_parser("search", help="one job over the whole range (no windows, not resumable)")
    p.add_argument("query", help="SPL (or @file.spl)")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--earliest", default="-24h@h")
    p.add_argument("--latest", default="now")
    common(p)

    for name, hlp in (("status", "show job status"), ("touch", "extend a job's lifetime")):
        p = sub.add_parser(name, help=hlp)
        p.add_argument("sid")
        if name == "touch":
            p.add_argument("--ttl", type=int, default=86400)
    p = sub.add_parser("delete", aliases=["cancel"], help="delete one or more jobs (SIDs or search URLs)")
    p.add_argument("sids", nargs="+")
    p.add_argument("--verify-minutes", type=int, default=10,
                   help="how long to wait for a job to disappear after each method (default 10)")

    a = ap.parse_args()
    if not a.base:
        sys.exit("No Splunk URL: set it in Voyager's Settings page, SPLUNK_BASE, or --base https://splunk.example.com")
    if a.insecure:
        requests.packages.urllib3.disable_warnings()
    host = urlparse(a.base).hostname
    sp = Splunk(a.base, a.locale, lambda quiet: find_cookies(a.cookies, a.db, host, quiet),
                verify=not a.insecure, timeout=a.timeout)
    while True:
        try:
            user, _ = sp.whoami()
            break
        except AuthError as e:
            if a.cmd in ("status", "touch", "delete", "cancel"):
                sys.exit(f"Auth failed ({e}). Reload a Splunk page with SplunkVoyager running, or refresh "
                         f"SPLUNK_COOKIE.")
            sp.reauth_wait(str(e))
    log(f"Authenticated as {user}")

    if a.cmd in ("delete", "cancel"):
        failed = []
        for raw in a.sids:
            sid, _ = parse_sid(raw)
            log(f"Deleting job {sid}")
            if sp.delete_job(sid, a.verify_minutes):
                log(f"  -> {sid} is gone")
            else:
                failed.append(sid)
                log(f"  -> could not remove {sid}")
        if failed:
            log("Some jobs could not be removed. Splunk still deletes them when their lifetime runs out "
                "(see `status <SID>` for ttl); otherwise ask a Splunk admin to remove the dispatch "
                "directory: " + ", ".join(failed))
            sys.exit(1)
        return

    if a.cmd in ("status", "touch"):
        sid, _ = parse_sid(a.sid)
        if a.cmd == "status":
            c = sp.job(sid)
            if c:
                print(fmt_status(c))
                describe_done(c) if c.get("isDone") else None
            else:
                print(f"Job {sid} not found (expired?)")
        else:
            ok, msg = sp.control(sid, "setttl", ttl=str(a.ttl))
            print("TTL updated" if ok else f"Failed: {msg}")
        return

    try:
        if a.cmd == "run":
            if a.retry_failed:
                man = Manifest(a.out_dir)
                if man.exists():
                    man.load()
                    for w in man.windows:
                        if w["state"] == "failed":
                            w["state"], w["attempts"] = "pending", 0
                    man.save()
            run(a, sp)
        elif a.cmd == "sid":
            sid, url_app = parse_sid(a.sid)
            cmd_single(a, sp, sid, a.app or url_app or sp.default_app, a.resume)
        else:
            q = Path(a.query[1:]).read_text(encoding="utf-8") if a.query.startswith("@") else a.query
            app = a.app or sp.default_app
            sid = sp.create(app, q, parse_time(a.earliest), parse_time(a.latest), a.job_ttl,
                            level=a.search_level or "fast")
            log(f"Started job SID={sid}  (resume with: sid {sid} --app {app} -o {a.out} --resume)")
            cmd_single(a, sp, sid, app, False)
    except KeyboardInterrupt:
        log("Interrupted. Splunk jobs keep running; rerun the same command to continue.")
        sys.exit(130)


if __name__ == "__main__":
    main()

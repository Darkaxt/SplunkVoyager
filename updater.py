"""Self-update from the git checkout this app runs from.

check()  - git fetch; how many commits behind, and whether an update can be applied safely
apply()  - fast-forward to the upstream branch; reinstall requirements if requirements.txt changed
Only fast-forwards a clean checkout: local edits to tracked files, another branch or diverged history
mean nothing is touched. Everything is logged; a failed check (no network, no git) is not an error.
"""
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
STATE = HERE / "data" / "update_state.json"     # last applied update (for rollback) and skipped commits
RESTART_CODE = 42                               # exit code of the server asking its supervisor to restart it

status = {"enabled": False, "checked": None, "behind": 0, "current": None, "upstream": None, "error": None,
          "blocked": None, "applying": False, "log": []}
_lock = threading.Lock()


def _git(*args, timeout=60):
    kw = {}
    if os.name == "nt":
        kw["creationflags"] = 0x08000000        # CREATE_NO_WINDOW
    r = subprocess.run(["git", "-C", str(HERE), *args], capture_output=True, text=True, timeout=timeout,
                       stdin=subprocess.DEVNULL, **kw)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).strip().splitlines()[-1] if (r.stderr or r.stdout).strip()
                           else f"git {args[0]} failed")
    return r.stdout.strip()


def _note(msg, log=None):
    status["log"] = (status["log"] + [f"{datetime.now():%Y-%m-%d %H:%M} {msg}"])[-20:]
    if log:
        log(msg)


def read_state():
    try:
        return json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def write_state(**kv):
    s = read_state()
    s.update(kv)
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(s, indent=2), encoding="utf-8")


def is_checkout():
    return (HERE / ".git").exists()


def check(fetch=True):
    """Refresh `status`. Returns the number of commits the checkout is behind (0 if it can't tell)."""
    with _lock:
        status["error"] = status["blocked"] = None
        status["checked"] = datetime.now().isoformat(timespec="seconds")
        if not is_checkout():
            status["error"] = "not a git checkout (installed from a zip?): updating needs `git clone`"
            return 0
        try:
            if fetch:
                _git("fetch", "--quiet", "origin", timeout=120)
            status["current"] = _git("rev-parse", "--short", "HEAD")
            try:
                status["upstream"] = _git("rev-parse", "--short", "@{u}")
            except RuntimeError:
                status["blocked"] = "the current branch has no upstream branch"
                return 0
            behind = int(_git("rev-list", "--count", "HEAD..@{u}") or 0)
            ahead = int(_git("rev-list", "--count", "@{u}..HEAD") or 0)
            status["behind"] = behind
            if behind and ahead:
                status["blocked"] = f"local commits not on GitHub ({ahead}): update by hand"
            elif behind and _git("status", "--porcelain", "--untracked-files=no"):
                status["blocked"] = "files of the app were edited locally: update by hand (git stash / git pull)"
            elif behind and _git("rev-parse", "@{u}") in read_state().get("skip", []):
                status["blocked"] = "this version failed to start before and was rolled back"
            return behind
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
            status["error"] = f"update check failed: {e}"
            return 0


def _req_hash():
    try:
        return hashlib.sha256((HERE / "requirements.txt").read_bytes()).hexdigest()
    except OSError:
        return ""


def apply(log=print):
    """Fast-forward to upstream. Returns True when the code changed (the server must restart)."""
    if not check(fetch=False) or status["blocked"]:
        return False
    with _lock:
        status["applying"] = True
        try:
            old, req = _git("rev-parse", "HEAD"), _req_hash()
            new = _git("rev-parse", "@{u}")
            _git("merge", "--ff-only", "--quiet", "@{u}")
            _note(f"updated {old[:7]} -> {new[:7]}", log)
            if _req_hash() != req:
                _note("requirements.txt changed: installing", log)
                r = subprocess.run([sys.executable, "-m", "pip", "install", "-q", "-r", str(HERE / "requirements.txt")],
                                   capture_output=True, text=True, timeout=900)
                if r.returncode != 0:
                    _git("reset", "--hard", "--quiet", old)
                    write_state(skip=read_state().get("skip", []) + [new])
                    _note(f"pip install failed, back to {old[:7]}: {(r.stderr or r.stdout).strip()[-300:]}", log)
                    return False
            write_state(previous=old, applied=new, applied_at=time.time())
            return True
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
            _note(f"update failed: {e}", log)
            return False
        finally:
            status["applying"] = False


def rollback(log=print):
    """After a restart that failed right after an update: back to the previous commit, skip the broken one."""
    s = read_state()
    if not s.get("previous") or time.time() - s.get("applied_at", 0) > 300:
        return False
    try:
        _git("reset", "--hard", "--quiet", s["previous"])
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
        log(f"rollback failed: {e}")
        return False
    write_state(skip=s.get("skip", []) + [s["applied"]], previous=None, applied=None, applied_at=0)
    log(f"the update to {s['applied'][:7]} did not start: rolled back to {s['previous'][:7]}; "
        f"that version will be skipped")
    return True


def confirm_started():
    """The updated server is up: forget the rollback point."""
    if read_state().get("previous"):
        write_state(previous=None, applied_at=0)


def loop(request_restart, log, mode, interval_min):
    """Background thread in the server: check every interval; apply and restart when mode == 'apply'."""
    status["enabled"] = mode != "off"
    if mode == "off":
        return
    time.sleep(30)        # let the server start first
    while True:
        try:
            import voyager_settings
            s = voyager_settings.load()
            mode, interval_min = s.get("auto_update", mode), s.get("update_interval", interval_min)
            status["enabled"] = mode != "off"
            if mode != "off":
                behind = check()
                if behind and not status["blocked"]:
                    _note(f"{behind} new commit(s) on GitHub", log)
                    if mode == "apply" and apply(log):
                        request_restart()
                        return
        except Exception as e:          # never let the updater take the server down
            status["error"] = str(e)
        time.sleep(max(5, int(interval_min)) * 60)

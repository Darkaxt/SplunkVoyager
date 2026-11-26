"""Investigations and their jobs (network analysis, entity mapping) for the web GUI.

Layout under data/investigations/<slug>/:
  investigation.json
  network/<job id>/   export/ (Splunk windows), requests.jsonl, analysis.json, report.html, findings.json
  entities/           one pivot case shared by all entity jobs: case.json, seeds/, graph.html
  jobs/<job id>/      job.json (steps, status), log.txt
Jobs run in jobrun.py, detached from the web app.
"""
import glob
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import voyager_settings
from app.config import DATA_DIR, logger

ROOT = Path(__file__).resolve().parents[2]
INV_ROOT = Path(DATA_DIR) / "investigations"
PY = "{python}"   # replaced by jobrun with its own interpreter


def _now():
    return datetime.now().isoformat(timespec="seconds")


def _read(p, default=None):
    for _ in range(10):
        try:
            return json.loads(Path(p).read_text(encoding="utf-8"))
        except FileNotFoundError:
            return default
        except (OSError, ValueError):
            time.sleep(0.1)
    return default


def _write(p, data):
    p = Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".web.tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    for _ in range(40):
        try:
            os.replace(tmp, p)
            return
        except PermissionError:
            time.sleep(0.25)
    p.write_text(tmp.read_text(encoding="utf-8"), encoding="utf-8")


def slugify(name):
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:48] or "investigation"
    base, i = s, 2
    while (INV_ROOT / s).exists():
        s, i = f"{base}-{i}", i + 1
    return s


def inv_dir(slug):
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", slug or ""):
        raise ValueError("bad investigation id")
    d = INV_ROOT / slug
    if not (d / "investigation.json").is_file():
        raise FileNotFoundError(slug)
    return d


# ------------------------------------------------------------------ investigations
def list_investigations():
    out = []
    for f in sorted(INV_ROOT.glob("*/investigation.json")):
        inv = _read(f, {})
        jobs = [job_status(f.parent, j.name, tail=0) for j in sorted((f.parent / "jobs").glob("*")) if j.is_dir()]
        inv["jobs_running"] = sum(j["status"] in ("running", "waiting", "queued") for j in jobs)
        inv["jobs_total"] = len(jobs)
        out.append(inv)
    return sorted(out, key=lambda x: x.get("created", ""), reverse=True)


def create_investigation(name, earliest, latest, notes="", instance=""):
    if not name.strip():
        raise ValueError("name is required")
    if not earliest:
        raise ValueError("earliest time is required")
    inst = voyager_settings.instance(instance or None)
    if not inst.get("base"):
        raise ValueError("Add a Splunk instance in Settings first")
    INV_ROOT.mkdir(parents=True, exist_ok=True)
    slug = slugify(name)
    d = INV_ROOT / slug
    (d / "jobs").mkdir(parents=True)
    inv = {"slug": slug, "name": name.strip(), "earliest": earliest, "latest": latest or "now",
           "notes": notes, "instance": inst["name"], "created": _now()}
    _write(d / "investigation.json", inv)
    return inv


def get_investigation(slug):
    d = inv_dir(slug)
    inv = _read(d / "investigation.json", {})
    jobs = [job_status(d, j.name) for j in (d / "jobs").glob("*") if j.is_dir()]
    jobs.sort(key=lambda j: (j.get("created") or "", j["id"]), reverse=True)   # newest first
    inv["jobs"] = jobs
    net = []
    for j in jobs:
        if j["kind"] != "network":
            continue
        nd = d / "network" / j["id"]
        net.append({"job": j["id"], "title": j["title"], "status": j["status"],
                    "report": (nd / "report.html").is_file() and f"network/{j['id']}/report.html",
                    "findings": _read(nd / "findings.json")})
    inv["network"] = net
    ed = d / "entities"
    case = _read(ed / "case.json", {"seeds": []})
    inv["entities"] = {"seeds": [{"value": s["value"], "earliest": s.get("earliest"), "latest": s.get("latest")}
                                 for s in case.get("seeds", [])],
                       "graph": (ed / "graph.html").is_file() and "entities/graph.html",
                       "csv": (ed / "graph_entities.csv").is_file() and "entities/graph_entities.csv"}
    return inv


def delete_investigation(slug):
    """Stop the investigation's jobs (and their Splunk searches), then remove its folder."""
    import shutil
    d = inv_dir(slug)
    for j in (d / "jobs").glob("*"):
        if j.is_dir() and job_status(d, j.name, tail=0)["status"] in ("running", "waiting", "queued"):
            stop_job(slug, j.name)
    for _ in range(20):          # Windows: a process that just stopped may still hold a file for a moment
        shutil.rmtree(d, ignore_errors=True)
        if not d.exists():
            return
        time.sleep(0.5)
    raise RuntimeError(f"could not remove everything in {d}; close any file open from it and try again")


def update_investigation(slug, **kv):
    d = inv_dir(slug)
    inv = _read(d / "investigation.json", {})
    inv.update({k: v for k, v in kv.items() if k in ("name", "earliest", "latest", "notes", "instance")})
    _write(d / "investigation.json", inv)
    return inv


# ------------------------------------------------------------------ jobs
def _new_job(d, kind, title, steps, lock=None, meta=None):
    jid = f"{kind}-{datetime.now():%Y%m%d-%H%M%S}"
    n = 2
    while (d / "jobs" / jid).exists():
        jid = f"{kind}-{datetime.now():%Y%m%d-%H%M%S}-{n}"
        n += 1
    jd = d / "jobs" / jid
    jd.mkdir(parents=True)
    job = {"id": jid, "kind": kind, "title": title, "created": _now(), "status": "queued", "step": 0,
           "steps": steps, "lock": lock, "meta": meta or {}}
    _write(jd / "job.json", job)
    return jid


def _spawn(jd):
    kw = {"cwd": str(ROOT), "stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
          "close_fds": True}
    if os.name == "nt":
        # own process group (Ctrl+C in the run.py console doesn't reach it) and a hidden console for the steps
        kw["creationflags"] = 0x00000200 | 0x08000000   # CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
    else:
        kw["start_new_session"] = True
    subprocess.Popen([sys.executable, str(ROOT / "jobrun.py"), str(jd)], **kw)


def start_job(slug, jid):
    jd = inv_dir(slug) / "jobs" / jid
    st = job_status(inv_dir(slug), jid, tail=0)
    if st["status"] in ("running", "waiting"):
        raise RuntimeError("job is already running")
    job = _read(jd / "job.json")
    job.update(status="queued", error=None)
    _write(jd / "job.json", job)
    _spawn(jd)
    return jid


def stop_job(slug, jid):
    jd = inv_dir(slug) / "jobs" / jid
    job = _read(jd / "job.json", {})
    pid = job.get("pid")
    if pid:
        try:
            import psutil
            p = psutil.Process(int(pid))
            kids = p.children(recursive=True)
            for k in kids:
                k.terminate()
            p.terminate()
            psutil.wait_procs(kids + [p], timeout=10)
        except Exception as e:  # already gone
            logger.info(f"stop {jid}: {e}")
    job = _read(jd / "job.json", {})
    if job.get("status") in ("running", "waiting", "queued"):
        job.update(status="stopped", pid=None, ended=_now())
        _write(jd / "job.json", job)
    # cancel the Splunk searches the stopped export had running (they'd otherwise run on until they expire)
    sids = []
    st = (job.get("steps") or [{}])[min(job.get("step", 0), max(len(job.get("steps") or [1]) - 1, 0))]
    for g in st.get("progress", []):
        for m in glob.glob(g):
            sids += [w["sid"] for w in (_read(m, {}) or {}).get("windows", [])
                     if w.get("sid") and w.get("state") in ("running", "downloading")]
    if sids:
        kw = {"cwd": str(ROOT), "stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
        if os.name == "nt":
            kw["creationflags"] = 0x00000200 | 0x08000000
        else:
            kw["start_new_session"] = True
        subprocess.Popen([sys.executable, str(ROOT / "splunk_export.py"), "delete", *sids, "--verify-minutes", "2"], **kw)
        logger.info(f"stop {jid}: cancelling {len(sids)} Splunk search(es)")
    return jid


def delete_job(slug, jid):
    d = inv_dir(slug)
    st = job_status(d, jid, tail=0)
    if st["status"] in ("running", "waiting", "queued"):
        raise RuntimeError("stop the job first")
    import shutil
    shutil.rmtree(d / "jobs" / jid, ignore_errors=True)
    if st["kind"] == "network":
        shutil.rmtree(d / "network" / jid, ignore_errors=True)


def _alive(pid):
    if not pid:
        return False
    try:
        import psutil
        if not psutil.pid_exists(int(pid)):
            return False
        return any("jobrun.py" in c for c in psutil.Process(int(pid)).cmdline())
    except Exception:
        return False


def _progress(job):
    """Windows done / total across the exporter manifests of the current step."""
    st = job["steps"][min(job.get("step", 0), len(job["steps"]) - 1)] if job.get("steps") else {}
    done = total = 0
    since = (job.get("step_started") or 0) - 2
    for g in st.get("progress", []):
        for m in glob.glob(g):
            if os.path.getmtime(m) < since:
                continue          # manifest of earlier work (another value of the same case)
            man = _read(m, {})
            ws = man.get("windows", [])
            total += len(ws)
            done += sum(w.get("state") == "done" for w in ws)
    return {"done": done, "total": total} if total else None


def job_status(d, jid, tail=40):
    jd = Path(d) / "jobs" / jid
    job = _read(jd / "job.json", {}) or {"id": jid, "kind": "?", "title": jid, "status": "missing", "steps": []}
    if job.get("status") in ("running", "waiting") and not _alive(job.get("pid")):
        job["status"] = "interrupted"     # the runner died (reboot, killed): Resume continues at this step
    steps = job.get("steps", [])
    out = {k: job.get(k) for k in ("id", "kind", "title", "created", "started", "ended", "status", "rc", "error", "meta")}
    out["step"] = job.get("step", 0)
    out["steps"] = [s["name"] for s in steps]
    out["progress"] = _progress(job) if job.get("status") in ("running", "interrupted", "stopped") else None
    if tail:
        try:
            with open(jd / "log.txt", encoding="utf-8", errors="replace") as fh:
                out["log"] = "".join(fh.readlines()[-tail:])
        except OSError:
            out["log"] = ""
    return out


def read_log(slug, jid, tail=400):
    p = inv_dir(slug) / "jobs" / jid / "log.txt"
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            return "".join(fh.readlines()[-tail:])
    except OSError:
        return ""


def _instance(d):
    """The investigation's Splunk instance (falls back to the default one if it was removed from Settings)."""
    inst = voyager_settings.instance(_read(d / "investigation.json", {}).get("instance") or None)
    if not inst.get("base"):
        raise ValueError("Add a Splunk instance in Settings first")
    return inst


def _common_export_args(d):
    """Where and how searches run: --base/--locale/--app of the investigation's instance."""
    s = voyager_settings.load()
    inst = _instance(d)
    args = ["--base", inst["base"], "--locale", inst["locale"], "--max-jobs", str(s.get("max_jobs") or 2)]
    if inst.get("app"):
        args += ["--app", inst["app"]]
    return args


# ------------------------------------------------------------------ module: network analysis (Payload Analyzer)
def start_network(slug, base, extract="", fields=None, earliest=None, latest=None, chunk="1d", title=""):
    from network_feed import build_query
    d = inv_dir(slug)
    inv = _read(d / "investigation.json", {})
    spl = build_query(base, extract, fields)
    earliest, latest = earliest or inv["earliest"], latest or inv.get("latest") or "now"
    jid_dir = d / "network"
    title = title.strip() or base.strip().splitlines()[0][:80]
    # the job id is known only after creation: create, then fill the paths in
    jid = _new_job(d, "network", title, [], meta={"base": base, "extract": extract, "fields": fields or {},
                                                 "earliest": earliest, "latest": latest, "chunk": chunk, "spl": spl})
    nd = jid_dir / jid
    nd.mkdir(parents=True, exist_ok=True)
    (nd / "query.spl").write_text(spl, encoding="utf-8")
    pa = ROOT / "payload_analyzer"
    common = _common_export_args(d)     # --base B --locale L, then --max-jobs N [--app A]
    steps = [
        # splunk_export.py: --base/--locale are global options (before "run"), the rest belong to "run"
        {"name": "Splunk export", "argv": [PY, str(ROOT / "splunk_export.py")] + common[:4] + [
                                           "run", "@" + str(nd / "query.spl"),
                                           "--earliest", earliest, "--latest", latest, "--chunk", chunk,
                                           "--out-dir", str(nd / "export"), "-f", "jsonl"] + common[4:],
         "progress": [str(nd / "export" / "manifest.json")]},
        {"name": "Merge time windows", "argv": [PY, str(ROOT / "network_feed.py"), "merge", str(nd / "export"),
                                                "-o", str(nd / "requests.jsonl")]},
        {"name": "Payload analysis", "argv": [PY, "-I", str(pa / "payload_analyzer.py"), "pipeline",
                                              str(nd / "requests.jsonl"), "-o", str(nd / "analysis.json")]},
        {"name": "HTML report", "argv": [PY, "-I", str(pa / "report_builder.py"), str(nd / "analysis.json"),
                                         "-o", str(nd / "report.html")]},
        {"name": "Findings for the entity mapper", "argv": [PY, str(ROOT / "network_feed.py"), "iocs",
                                                             str(nd / "analysis.json"), "-o", str(nd / "findings.json")]},
    ]
    job = _read(d / "jobs" / jid / "job.json")
    job["steps"] = steps
    _write(d / "jobs" / jid / "job.json", job)
    _spawn(d / "jobs" / jid)
    return jid


# ------------------------------------------------------------------ module: entity evolution mapper (pivot graph)
def _build_step(d, slug, bin_min=5, group="sourcetype"):
    ed = d / "entities"
    inst = _instance(d)
    links = ["--splunk-base", inst["base"], "--locale", inst["locale"]] + (["--app", inst["app"]] if inst.get("app") else [])
    return {"name": "Build graph", "argv": [PY, str(ROOT / "pivot_graph.py"), "build", str(ed), "-o", str(ed / "graph.html"),
                                            "--bin", str(bin_min), "--group", group] + links + [
                                            "--voyager-api", f"/api/inv/{slug}/entities",
                                            "--title", _read(d / "investigation.json", {}).get("name", "IOC pivot graph")]}


def start_entities(slug, values, earliest=None, latest=None, include="", max_events=500000, bin_min=5,
                   group="sourcetype", title="", reset_range=False):
    d = inv_dir(slug)
    inv = _read(d / "investigation.json", {})
    values = [v.strip() for v in values if v and v.strip()]
    if not values:
        raise ValueError("no values to map")
    earliest, latest = earliest or inv["earliest"], latest or inv.get("latest") or "now"
    ed = d / "entities"
    ed.mkdir(parents=True, exist_ok=True)
    common = _common_export_args(d)
    steps = []
    for v in values:
        argv = [PY, str(ROOT / "pivot_graph.py"), "seed", str(ed), v, "--earliest", earliest, "--latest", latest,
                "--max-events", str(int(max_events))] + common
        if include.strip():
            argv += ["--include", include.strip()]
        if reset_range:
            argv.append("--reset-range")   # a value already mapped with another range is searched again
        steps.append({"name": f"Search {v[:60]}", "argv": argv,
                      "progress": [str(ed / "seeds" / "*" / "stage1" / "manifest.json"),
                                   str(ed / "seeds" / "*" / "raw" / "*" / "manifest.json")]})
    steps.append(_build_step(d, slug, bin_min, group))
    title = title.strip() or ("Map " + ", ".join(values))[:100]
    jid = _new_job(d, "entities", title, steps, lock="entities",
                   meta={"values": values, "earliest": earliest, "latest": latest})
    _spawn(d / "jobs" / jid)
    return jid


def rebuild_graph(slug, bin_min=5, group="sourcetype"):
    d = inv_dir(slug)
    if not (d / "entities" / "case.json").is_file():
        raise ValueError("no entity searches yet")
    jid = _new_job(d, "entities", "Rebuild graph", [_build_step(d, slug, bin_min, group)], lock="entities")
    _spawn(d / "jobs" / jid)
    return jid

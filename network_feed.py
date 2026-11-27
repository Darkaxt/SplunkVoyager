"""Bridge between the Splunk exporter and Payload Analyzer.

  build_query(...)                         SPL: your base search + optional extraction + the request aggregation
  python network_feed.py merge EXPORT_DIR -o requests.jsonl
        merges the per-window results of an export run into one line per (site, uri_path, uri_query):
        counts summed, first/last time kept, sources/statuses/actions united, times written in UTC
  python network_feed.py analyse requests.jsonl -o analysis.json
        Payload Analyzer in two stages (decode to a JSON Lines intermediate, then analyse it as a stream):
        the same result as its `pipeline` command, which loads its whole intermediate into memory at once
        and runs out of memory on large web logs
  python network_feed.py iocs analysis.json -o findings.json
        attack sources, callback hosts/URLs and targets from Payload Analyzer's output, ranked by requests
"""
import argparse
import glob
import ipaddress
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

FIELDS = ("site", "uri_path", "uri_query", "src", "status", "action")
# Request and response sizes, first field present wins. Names vary by source: IIS/W3C use cs_bytes (client to
# server, the request) and sc_bytes (server to client, the response); some feeds use cs_B/sc_B or bytes_out/bytes_in.
SIZE_FIELDS = {"req_bytes": "cs_bytes,cs_B,bytes_out", "resp_bytes": "sc_bytes,sc_B,bytes_in"}
SIZE_SUMS = ("req_bytes", "req_n", "resp_bytes", "resp_n")
FIELD_RE = re.compile(r"^[A-Za-z_][\w.:\-{}]*$")


def _size_eval(name, spec):
    names = [n.strip() for n in str(spec or "").split(",") if n.strip()]
    for n in names:
        if not FIELD_RE.match(n):
            raise ValueError(f"field name for {name} is not a plain Splunk field name: {n!r}")
    if not names:
        return None
    if len(names) == 1:
        return f"{name}=tonumber('{names[0]}')"
    return f"{name}=coalesce(" + ", ".join(f"tonumber('{n}')" for n in names) + ")"


def build_query(base, extract="", fields=None):
    """SPL that yields one row per request group, in the shape Payload Analyzer reads.

    fields maps Payload Analyzer's names (site, uri_path, uri_query, src, status, action) to the field names in
    your data; leave a name as is when the data already uses it. Nothing is assumed to be parsed: put rex/eval
    lines in `extract` to derive the fields first. req_bytes / resp_bytes take a comma-separated list of size
    fields (first present wins; empty = the defaults, "-" = no sizes); missing size fields only leave the sizes out.
    """
    sizes = {k: str((fields or {}).get(k) or "").strip() or v for k, v in SIZE_FIELDS.items()}
    sizes = {k: "" if v == "-" else v for k, v in sizes.items()}
    base = (base or "").strip()
    if not base:
        raise ValueError("base search is empty")
    lines = [base]
    if extract and extract.strip():
        ex = extract.strip()
        lines.append(ex if ex.startswith("|") else "| " + ex)
    fields = {k: (v or k).strip() for k, v in (fields or {}).items() if k in FIELDS}
    evals = []
    for k in FIELDS:
        src = fields.get(k, k)
        if not FIELD_RE.match(src):
            raise ValueError(f"field name for {k} is not a plain Splunk field name: {src!r}")
        if src != k:
            evals.append(f"{k}='{src}'")
    size_evals = [e for e in (_size_eval(k, v) for k, v in sizes.items()) if e]
    evals += size_evals
    if evals:
        lines.append("| eval " + ", ".join(evals))
    agg = ("| stats count min(_time) as et max(_time) as lt values(src) as src values(status) as status "
           "values(action) as action")
    if any(e.startswith("req_bytes=") for e in size_evals):
        agg += " sum(req_bytes) as req_bytes count(req_bytes) as req_n"
    if any(e.startswith("resp_bytes=") for e in size_evals):
        agg += " sum(resp_bytes) as resp_bytes count(resp_bytes) as resp_n max(resp_bytes) as resp_max"
    lines += [
        '| fillnull value="" uri_query',
        "| where isnotnull(site) AND isnotnull(uri_path)",
        agg + " by site uri_path uri_query",
    ]
    return "\n".join(lines)


def _list(v):
    if v is None or v == "":
        return []
    return [str(x) for x in v] if isinstance(v, list) else [str(v)]


def _num(v):
    if v in (None, ""):
        return None
    try:
        return float(v[0] if isinstance(v, list) else v)
    except (TypeError, ValueError, IndexError):
        return None


def _epoch(v):
    if v in (None, ""):
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        pass
    s = str(v).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def _utc(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if t is not None else None


def read_export(export_dir):
    import exportfiles
    files = exportfiles.parts(export_dir, "jsonl")
    if not files:
        raise SystemExit(f"No part files (part-*.jsonl, part-*.jsonl.zip or export.zip) in {export_dir}")
    for f in files:
        with f.open() as fh:
            for line in fh:
                if line.strip():
                    r = json.loads(line)
                    yield r.get("result", r) if isinstance(r, dict) else r


def merge(export_dir, out):
    groups = {}
    rows = 0
    for r in read_export(export_dir):
        rows += 1
        key = (str(r.get("site", "")), str(r.get("uri_path", "")), str(r.get("uri_query", "") or ""))
        g = groups.get(key)
        if g is None:
            g = groups[key] = {"count": 0, "et": None, "lt": None, "src": set(), "status": set(), "action": set(),
                               "req_bytes": 0, "req_n": 0, "resp_bytes": 0, "resp_n": 0, "resp_max": None}
        try:
            g["count"] += int(float(r.get("count") or 0))
        except (TypeError, ValueError):
            pass
        et, lt = _epoch(r.get("et")), _epoch(r.get("lt"))
        if et is not None:
            g["et"] = et if g["et"] is None else min(g["et"], et)
        if lt is not None:
            g["lt"] = lt if g["lt"] is None else max(g["lt"], lt)
        for k in ("src", "status", "action"):
            g[k].update(_list(r.get(k)))
        for k in SIZE_SUMS:
            g[k] += _num(r.get(k)) or 0
        mx = _num(r.get("resp_max"))
        if mx is not None:
            g["resp_max"] = mx if g["resp_max"] is None else max(g["resp_max"], mx)
    tmp = Path(str(out) + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        for (site, path, query), g in sorted(groups.items()):
            row = {"site": site, "uri_path": path, "uri_query": query, "count": g["count"],
                   "et": _utc(g["et"]), "lt": _utc(g["lt"]), "src": sorted(g["src"]),
                   "status": sorted(g["status"]), "action": sorted(g["action"])}
            if g["req_n"]:
                row.update(req_bytes=int(g["req_bytes"]), req_n=int(g["req_n"]))
            if g["resp_n"]:
                row.update(resp_bytes=int(g["resp_bytes"]), resp_n=int(g["resp_n"]), resp_max=int(g["resp_max"] or 0))
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    os.replace(tmp, out)
    print(f"{rows:,} rows from the export windows -> {len(groups):,} request groups in {out}", file=sys.stderr)


def _run_tee(argv):
    """Run a stage, passing its output through, and tell whether it ran out of memory."""
    import subprocess
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                         errors="replace")
    oom = False
    for line in p.stdout:
        sys.stderr.write(line)
        oom = oom or "MemoryError" in line
    return p.wait(), oom


def analyse(requests_path, out, low_memory=False):
    """
    payload_assessor -> resolutions.jsonl.pax -> payload_analyzer, then the source fields point at the input.

    Full mode includes unremarkable parameters, so series cover all traffic. Payload Analyzer keeps every
    distinct parameter value in memory for that; on a large log it can run out. Then (or with low_memory) the
    analysis runs on matched parameters only: the same attack findings, but series only over those parameters.
    The mode used is written to <output>.mode.json.
    """
    import hashlib
    pa = Path(__file__).resolve().parent / "payload_analyzer"
    src, out = Path(requests_path).resolve(), Path(out).resolve()
    res = out.with_name(".resolutions-" + out.stem + ".jsonl.pax")      # keyed container, like the pipeline's own
    mode_file = out.with_name(out.stem + ".mode.json")
    modes = ["matched-only"] if low_memory else ["full", "matched-only"]
    try:
        for mode in modes:
            assess = [sys.executable, "-I", str(pa / "payload_assessor.py"), str(src), "-o", str(res), "--format", "jsonl"]
            if mode == "full":
                assess.append("--include-unmatched")
            rc, oom = _run_tee(assess)
            if rc == 0:
                rc, oom = _run_tee([sys.executable, "-I", str(pa / "payload_analyzer.py"), str(res), "-o", str(out)])
            if rc == 0:
                break
            if oom and mode == "full":
                print("\nOut of memory with every parameter included: running again on matched parameters only "
                      "(same attack findings; series only over those parameters).\n", file=sys.stderr, flush=True)
                continue
            raise SystemExit(rc)
        mode_file.write_text(json.dumps({"mode": mode, "reason": "low-memory option" if low_memory else
                                         ("out of memory in full mode" if mode != "full" else "")}), encoding="utf-8")
        h = hashlib.sha256()
        with open(src, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        old_sha = hashlib.sha256()
        # the analyzer hashes the decoded intermediate; recompute it the same way to find it in the output
        sys.path.insert(0, str(pa))
        import paxio
        with paxio.open_binary_in(res) as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                old_sha.update(chunk)
        repl = [(json.dumps(str(res)), json.dumps(str(src))), (json.dumps(old_sha.hexdigest()), json.dumps(h.hexdigest()))]
        for f in [out] + sorted(out.parent.glob(out.name.split(".")[0] + ".determined*")):
            _replace_all(f, repl)
    finally:
        res.unlink(missing_ok=True)


def _replace_all(path, repl, chunk=1 << 20):
    """Replace every occurrence of each (unique) string, streaming the file; matches across chunk edges included."""
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    keep = max(len(a) for a, _ in repl) - 1
    with open(path, "r", encoding="utf-8", newline="") as fi, open(tmp, "w", encoding="utf-8", newline="") as fo:
        buf = ""
        for part in iter(lambda: fi.read(chunk), ""):
            buf += part
            for a, b in repl:
                buf = buf.replace(a, b)
            fo.write(buf[:-keep] if keep and len(buf) > keep else "" if keep else buf)
            buf = buf[-keep:] if keep and len(buf) > keep else ("" if not keep else buf)
        fo.write(buf)
    os.replace(tmp, path)


NOT_ATTACK = {"not_attack", "undetermined", None}


def _kind(v):
    try:
        ip = ipaddress.ip_address(v)
        return "ip", (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
    except ValueError:
        return "host", v.lower() in ("localhost",)


def iocs(analysis_path, out):
    d = json.loads(Path(analysis_path).read_text(encoding="utf-8"))
    src = defaultdict(lambda: {"requests": 0, "categories": set(), "first": None, "last": None, "targets": set()})
    cb = defaultdict(lambda: {"units": 0, "categories": set(), "kind": "", "internal": False})
    tg = defaultdict(lambda: {"requests": 0, "categories": set(), "paths": set()})
    for u in d.get("units", []):
        cat = u.get("effective_category") or (u.get("analysis") or {}).get("category")
        if cat in NOT_ATTACK:
            continue
        for oc in u.get("occurrences", []):
            act, tgt = oc.get("activity") or {}, oc.get("target") or {}
            n = int(act.get("request_count") or 0)
            for ip in act.get("source_ips") or []:
                s = src[ip]
                s["requests"] += n
                s["categories"].add(cat)
                s["targets"].add(tgt.get("site", ""))
                for k, f in (("first", min), ("last", max)):
                    v = act.get("first_seen" if k == "first" else "last_seen")
                    if v:
                        s[k] = v if s[k] is None else f(s[k], v)
            if tgt.get("site"):
                t = tg[tgt["site"]]
                t["requests"] += n
                t["categories"].add(cat)
                t["paths"].add(tgt.get("uri_path", ""))
        art = (u.get("analysis") or {}).get("artifacts") or {}
        for h in art.get("hosts") or []:
            k, internal = _kind(h)
            c = cb[h]
            c["units"] += 1
            c["categories"].add(cat)
            c["kind"], c["internal"] = k, internal
        for url in art.get("urls") or []:
            c = cb[url]
            c["units"] += 1
            c["categories"].add(cat)
            c["kind"] = "url"
    res = {
        "sources": sorted(({"value": k, "requests": v["requests"], "categories": sorted(v["categories"]),
                            "first": v["first"], "last": v["last"], "targets": sorted(v["targets"])}
                           for k, v in src.items()), key=lambda x: (-x["requests"], x["value"])),
        "callbacks": sorted(({"value": k, "kind": v["kind"], "internal": v["internal"], "units": v["units"],
                              "categories": sorted(v["categories"])} for k, v in cb.items()),
                            key=lambda x: (x["internal"], -x["units"], x["value"])),
        "targets": sorted(({"site": k, "requests": v["requests"], "paths": len(v["paths"]),
                            "categories": sorted(v["categories"])} for k, v in tg.items()),
                          key=lambda x: (-x["requests"], x["site"])),
        "categories": (d.get("meta") or {}).get("effective_category_counts") or (d.get("meta") or {}).get("category_counts"),
    }
    Path(out).write_text(json.dumps(res, indent=1), encoding="utf-8")
    print(f"{len(res['sources'])} attack sources, {len(res['callbacks'])} callback artifacts, "
          f"{len(res['targets'])} targeted sites -> {out}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("merge")
    m.add_argument("export_dir")
    m.add_argument("-o", "--output", required=True)
    an = sub.add_parser("analyse", help="run Payload Analyzer on merged requests without loading everything at once")
    an.add_argument("requests")
    an.add_argument("-o", "--output", required=True)
    an.add_argument("--low-memory", action="store_true",
                    help="matched parameters only: much less memory, same attack findings, series only over them")
    i = sub.add_parser("iocs")
    i.add_argument("analysis")
    i.add_argument("-o", "--output", required=True)
    q = sub.add_parser("query", help="print the SPL for a base search")
    q.add_argument("base")
    q.add_argument("--extract", default="")
    for f in FIELDS:
        q.add_argument(f"--{f.replace('_', '-')}", dest=f, default=f)
    for f, dflt in SIZE_FIELDS.items():
        q.add_argument(f"--{f.replace('_', '-')}", dest=f, default=dflt,
                       help=f"size fields, first present wins (default {dflt}; '-' = none)")
    a = ap.parse_args()
    if a.cmd == "merge":
        merge(a.export_dir, a.output)
    elif a.cmd == "analyse":
        analyse(a.requests, a.output, a.low_memory)
    elif a.cmd == "iocs":
        iocs(a.analysis, a.output)
    else:
        print(build_query(a.base, a.extract, {f: getattr(a, f) for f in (*FIELDS, *SIZE_FIELDS)}))


if __name__ == "__main__":
    main()

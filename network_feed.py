"""Bridge between the Splunk exporter and Payload Analyzer.

  build_query(...)                         SPL: your base search + optional extraction + the request aggregation
  python network_feed.py merge EXPORT_DIR -o requests.jsonl
        merges the per-window results of an export run into one line per (site, uri_path, uri_query):
        counts summed, first/last time kept, sources/statuses/actions united, times written in UTC
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
FIELD_RE = re.compile(r"^[A-Za-z_][\w.:\-{}]*$")


def build_query(base, extract="", fields=None):
    """SPL that yields one row per request group, in the shape Payload Analyzer reads.

    fields maps Payload Analyzer's names (site, uri_path, uri_query, src, status, action) to the field names in
    your data; leave a name as is when the data already uses it. Nothing is assumed to be parsed: put rex/eval
    lines in `extract` to derive the fields first.
    """
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
    if evals:
        lines.append("| eval " + ", ".join(evals))
    lines += [
        '| fillnull value="" uri_query',
        "| where isnotnull(site) AND isnotnull(uri_path)",
        "| stats count min(_time) as et max(_time) as lt values(src) as src values(status) as status "
        "values(action) as action by site uri_path uri_query",
    ]
    return "\n".join(lines)


def _list(v):
    if v is None or v == "":
        return []
    return [str(x) for x in v] if isinstance(v, list) else [str(v)]


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
    files = sorted(glob.glob(os.path.join(export_dir, "part-*.jsonl")))
    if not files:
        raise SystemExit(f"No part-*.jsonl files in {export_dir}")
    for f in files:
        with open(f, encoding="utf-8") as fh:
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
            g = groups[key] = {"count": 0, "et": None, "lt": None, "src": set(), "status": set(), "action": set()}
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
    tmp = Path(str(out) + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        for (site, path, query), g in sorted(groups.items()):
            fh.write(json.dumps({"site": site, "uri_path": path, "uri_query": query, "count": g["count"],
                                 "et": _utc(g["et"]), "lt": _utc(g["lt"]), "src": sorted(g["src"]),
                                 "status": sorted(g["status"]), "action": sorted(g["action"])},
                                ensure_ascii=False) + "\n")
    os.replace(tmp, out)
    print(f"{rows:,} rows from the export windows -> {len(groups):,} request groups in {out}", file=sys.stderr)


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
    i = sub.add_parser("iocs")
    i.add_argument("analysis")
    i.add_argument("-o", "--output", required=True)
    q = sub.add_parser("query", help="print the SPL for a base search")
    q.add_argument("base")
    q.add_argument("--extract", default="")
    for f in FIELDS:
        q.add_argument(f"--{f.replace('_', '-')}", dest=f, default=f)
    a = ap.parse_args()
    if a.cmd == "merge":
        merge(a.export_dir, a.output)
    elif a.cmd == "iocs":
        iocs(a.analysis, a.output)
    else:
        print(build_query(a.base, a.extract, {f: getattr(a, f) for f in FIELDS}))


if __name__ == "__main__":
    main()

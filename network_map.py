"""Attack map for a network analysis run: source addresses -> attacked sites, hourly evolution, progression.

  python network_map.py analysis.json -o attack_map.html [--title T] [--top-sources 80] [--sanitize]

Built from Payload Analyzer's own model (report_builder.build_model), so categories and SQL phases are the
same as in its report. Each distinct payload keeps its own first/last time; repeated identical requests are
counted but not timed individually.

Levels (per source + site pair, and per injection point = site + path + parameter) describe what the
payloads show, never whether an attack succeeded:
  0 probing       only probing payloads (does the injection point react?)
  1 enumeration   payloads reading structure: schema, counts, sizes, environment
  2 extraction    payloads reading stored data, or exploitation attempts (commands with actions, file reads...)
  3 sustained     level 2 and, on one injection point, the work progresses: 3+ distinct payloads whose phases
                  come in order (probing before enumeration before extraction), or 5+ distinct payloads whose
                  complexity rises over time
Pairs and levels are computed per source + site and per source + site + path (sites can be expanded).

Sizes: when requests.jsonl carries request/response sizes (req_bytes / resp_bytes from the export), each payload
gets the sizes of the exact request groups it came from (Payload Analyzer's line references), and each event an
estimate (its requests x the payload's average). The map scales arrows by request bytes and the packets flowing
back by response bytes; a payload's response is also compared with the median response of all requests to the
same site + path.
"""
import hashlib
import statistics
import argparse
import json
import math
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
PHASE_RANK = {"probing": 0, "enumeration": 1, "extraction": 2, "exploitation": 2}
LEVELS = [
    ("probing", "Only probing payloads: tests of whether the injection point reacts."),
    ("enumeration", "Payloads that read structure: schema, row counts, value sizes, environment."),
    ("extraction", "Payloads that read stored data, or exploitation attempts (commands with actions, file reads, writes)."),
    ("sustained", "Extraction or exploitation, and on one injection point the work progresses: 3+ distinct payloads "
                  "whose phases come in order, or 5+ distinct payloads whose complexity rises over time."),
]
SERIES_MIN = 5
ORDER_MIN = 3


def load_builder():
    sys.path.insert(0, str(HERE / "payload_analyzer"))
    import report_builder
    return report_builder


def complexity(u):
    """Rough size of a payload's work: distinct techniques, then decoded length (log scale)."""
    return round(len(u.get("rules") or []) + math.log10(1 + len(u.get("value") or "")), 3)


def _trend(points):
    """Complexity rising over time? Mean of the last third vs the first third, by first-seen order."""
    if len(points) < SERIES_MIN:
        return None
    pts = [c for _, c in sorted(points)]
    k = max(1, len(pts) // 3)
    first, last = sum(pts[:k]) / k, sum(pts[-k:]) / k
    return round(last - first, 3)


def _in_order(phase_times):
    """Phases reached in order: each later phase first seen after the earlier one (only phases present)."""
    seen = sorted((t, PHASE_RANK[p]) for p, t in phase_times.items() if p in PHASE_RANK)
    ranks = [r for _, r in seen]
    return len(set(ranks)) >= 2 and ranks == sorted(ranks)


def level_of(phases, points_by_ip):
    """(level index, reasons) for a set of payload phases and the injection points they hit."""
    top = max((PHASE_RANK.get(p, 0) for p in phases), default=0)
    reasons = []
    lvl = top
    if top == 2:
        for ip_key, info in points_by_ip.items():
            tr = info.get("trend")
            if info.get("in_order") and info["payloads"] >= ORDER_MIN:
                reasons.append(f"{info['payloads']} payloads with phases in order on {ip_key}")
            elif tr is not None and tr > 0 and info["payloads"] >= SERIES_MIN:
                reasons.append(f"{info['payloads']} distinct payloads on {ip_key}, complexity rising")
        if reasons:
            lvl = 3
    return lvl, reasons


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def find_requests(analysis_path, report, requests=None):
    """requests.jsonl the analysis was made from: given, beside the analysis, or the recorded source (sha checked)."""
    meta = report.get("meta") or {}
    cands = [Path(requests)] if requests else [Path(analysis_path).with_name("requests.jsonl"), Path(meta.get("source") or "")]
    want = meta.get("source_sha256")
    for c in cands:
        if c.name and c.is_file() and c.suffix == ".jsonl":
            if want and _sha256(c) != want:
                print(f"{c}: not the file this analysis was made from (sha256 differs); sizes left out", file=sys.stderr)
                continue
            return c
    return None


def load_sizes(report, requests_path):
    """{short unit id: size totals}, {(site, path): median response per request}, which sizes exist."""
    rb = load_builder()
    want = defaultdict(set)
    for u in report.get("units") or []:
        if (u.get("effective_category") or (u.get("analysis") or {}).get("category")) in (None, "not_attack"):
            continue
        for o in u.get("occurrences") or []:
            if o.get("source_jsonl_line"):
                want[int(o["source_jsonl_line"])].add(rb.short(u.get("unit_id")))
    rows, base, have = {}, defaultdict(list), {"req": False, "resp": False}
    with open(requests_path, encoding="utf-8") as fh:
        for i, line in enumerate(fh, 1):
            if '_bytes"' not in line:
                continue
            r = json.loads(line)
            if r.get("resp_n"):
                have["resp"] = True
                base[(r.get("site") or "", r.get("uri_path") or "")].append(r["resp_bytes"] / r["resp_n"])
            if r.get("req_n"):
                have["req"] = True
            if i in want:
                rows[i] = r
    per = defaultdict(lambda: {"req_b": 0, "req_n": 0, "resp_b": 0, "resp_n": 0, "resp_max": None})
    for line, uids in want.items():
        r = rows.get(line)
        if not r:
            continue
        for uid in uids:
            x = per[uid]
            x["req_b"] += r.get("req_bytes") or 0
            x["req_n"] += r.get("req_n") or 0
            x["resp_b"] += r.get("resp_bytes") or 0
            x["resp_n"] += r.get("resp_n") or 0
            if r.get("resp_max") is not None:
                x["resp_max"] = max(x["resp_max"] or 0, r["resp_max"])
    medians = {k: statistics.median(v) for k, v in base.items()}
    return dict(per), medians, have


def build(analysis_path, title=None, top_sources=80, sanitize=False, requests=None):
    rb = load_builder()
    report = json.loads(Path(analysis_path).read_text(encoding="utf-8"))
    m = rb.build_model(report)
    sizes, medians, have = {}, {}, {"req": False, "resp": False}
    rq = find_requests(analysis_path, report, requests) if requests is not False else None
    if rq:
        sizes, medians, have = load_sizes(report, rq)
    cats = {c[0]: {"label": c[1], "color": c[2]} for c in m.get("cats") or []}

    units = {}
    for u in m.get("units") or []:
        units[u["id"]] = {
            "id": u["id"], "cat": u["cat"], "phase": u.get("phase") or "probing", "site": u.get("site") or "",
            "path": u.get("path") or "", "param": u.get("param") or "", "value": (u.get("value") or "")[:600],
            "summary": (u.get("summary") or "")[:400], "rules": u.get("rules") or [], "first": u.get("first"),
            "last": u.get("last"), "count": u.get("count") or 0, "statuses": u.get("statuses") or [],
            "ips": u.get("ips") or [], "cx": complexity(u),
        }
        z = sizes.get(u["id"])
        if z:
            x = units[u["id"]]
            if z["req_n"]:
                x["req_avg"] = round(z["req_b"] / z["req_n"])
            if z["resp_n"]:
                x["resp_avg"] = round(z["resp_b"] / z["resp_n"])
                x["resp_max"] = z["resp_max"]
                med = medians.get((x["site"], x["path"]))
                if med:
                    x["resp_ratio"] = round(x["resp_avg"] / med, 2)

    # events: minute, cat, rule, target, requests, sources, phase, [[unit, n]...]
    events = []
    for ev in m.get("events") or []:
        t, cat, _rule, target, n, src, phase, members = ev[:8]
        slash = target.find("/")
        site, path = (target[:slash], target[slash:]) if slash >= 0 else (target, "")
        for uid, k in members or [[None, n]]:
            for ip in [s.strip() for s in str(src).split(",") if s.strip()] or ["unknown"]:
                e = {"t": int(t), "cat": cat, "phase": phase, "site": site, "path": path, "src": ip,
                     "u": uid, "n": int(k)}
                x = units.get(uid) or {}
                if "req_avg" in x:
                    e["bi"] = x["req_avg"] * e["n"]
                if "resp_avg" in x:
                    e["bo"] = x["resp_avg"] * e["n"]
                events.append(e)
    events.sort(key=lambda e: (e["t"], e["src"], e["site"]))

    # per pair and per injection point
    pairs = defaultdict(lambda: {"payloads": set(), "requests": 0, "first": None, "last": None, "cats": defaultdict(int),
                                 "phases": {}, "statuses": set(), "points": defaultdict(list), "bi": 0, "bo": 0})
    points = defaultdict(lambda: {"payloads": set(), "phases": {}, "cx": [], "requests": 0, "sources": set()})
    for e in events:
        u = units.get(e["u"]) or {}
        pkey = f"{e['site']}{e['path']} ? {u.get('param') or '-'}"
        p = pairs[(e["src"], e["site"])]
        p["payloads"].add(e["u"])
        p["requests"] += e["n"]
        p["bi"] += e.get("bi", 0)
        p["bo"] += e.get("bo", 0)
        p["first"] = e["t"] if p["first"] is None else min(p["first"], e["t"])
        p["last"] = e["t"] if p["last"] is None else max(p["last"], e["t"])
        p["cats"][e["cat"]] += 1
        p["phases"][e["phase"]] = min(p["phases"].get(e["phase"], e["t"]), e["t"])
        p["statuses"].update(u.get("statuses") or [])
        p["points"][pkey].append((e["t"], u.get("cx", 0), e["u"], e["phase"]))
        pt = points[pkey]
        if e["u"] not in pt["payloads"]:
            pt["cx"].append((e["t"], u.get("cx", 0)))
        pt["payloads"].add(e["u"])
        pt["phases"][e["phase"]] = min(pt["phases"].get(e["phase"], e["t"]), e["t"])
        pt["requests"] += e["n"]
        pt["sources"].add(e["src"])

    point_out = {}
    for k, pt in points.items():
        point_out[k] = {"payloads": len(pt["payloads"]), "requests": pt["requests"], "sources": len(pt["sources"]),
                        "phases": pt["phases"], "trend": _trend(pt["cx"]), "in_order": _in_order(pt["phases"])}
        lvl, why = level_of(pt["phases"], {k: point_out[k]})
        point_out[k].update(level=lvl, reasons=why)

    pair_out = _pairs_out(pairs)
    pairs_path = defaultdict(lambda: {"payloads": set(), "requests": 0, "first": None, "last": None, "cats": defaultdict(int),
                                      "phases": {}, "statuses": set(), "points": defaultdict(list), "bi": 0, "bo": 0})
    for e in events:
        u = units.get(e["u"]) or {}
        pkey = f"{e['site']}{e['path']} ? {u.get('param') or '-'}"
        p = pairs_path[(e["src"], e["site"] + "\t" + e["path"])]
        p["payloads"].add(e["u"])
        p["requests"] += e["n"]
        p["bi"] += e.get("bi", 0)
        p["bo"] += e.get("bo", 0)
        p["first"] = e["t"] if p["first"] is None else min(p["first"], e["t"])
        p["last"] = e["t"] if p["last"] is None else max(p["last"], e["t"])
        p["cats"][e["cat"]] += 1
        p["phases"][e["phase"]] = min(p["phases"].get(e["phase"], e["t"]), e["t"])
        p["statuses"].update(u.get("statuses") or [])
        p["points"][pkey].append((e["t"], u.get("cx", 0), e["u"], e["phase"]))
    path_pairs = _pairs_out(pairs_path)
    for p in path_pairs:
        p["site"], p["path"] = p["site"].split("\t", 1)
    path_level = defaultdict(int)
    for p in path_pairs:
        path_level[(p["site"], p["path"])] = max(path_level[(p["site"], p["path"])], p["level"])

    # sources and sites
    data = _finish(events, units, cats, pair_out, path_pairs, path_level, point_out, title, top_sources, sanitize)
    data["sizes"] = have
    return data


def _pairs_out(pairs):
    pair_out = []
    for (src, site), p in pairs.items():
        # this pair's own progression per injection point (its payloads only)
        own = {}
        for k, items in p["points"].items():
            seen, cx, ph = set(), [], {}
            for t, c, uid, phase in sorted(items):
                if uid not in seen:
                    seen.add(uid)
                    cx.append((t, c))
                ph[phase] = min(ph.get(phase, t), t)
            own[k] = {"payloads": len(seen), "trend": _trend(cx), "in_order": _in_order(ph)}
        lvl, why = level_of(p["phases"], own)
        pair_out.append({"src": src, "site": site, "payloads": len(p["payloads"]), "requests": p["requests"],
                         "first": p["first"], "last": p["last"], "cats": dict(p["cats"]), "phases": p["phases"],
                         "statuses": sorted(p["statuses"]), "level": lvl, "reasons": why,
                         "points": sorted(own), "bi": p["bi"], "bo": p["bo"]})
    return pair_out


def _finish(events, units, cats, pair_out, path_pairs, path_level, point_out, title, top_sources, sanitize):
    srcs = defaultdict(lambda: {"payloads": set(), "requests": 0, "first": None, "level": 0, "sites": set()})
    sites = defaultdict(lambda: {"payloads": set(), "requests": 0, "first": None, "level": 0, "sources": set()})
    for e in events:
        for d, other, key in ((srcs[e["src"]], e["site"], "sites"), (sites[e["site"]], e["src"], "sources")):
            d["payloads"].add(e["u"])
            d["requests"] += e["n"]
            d["first"] = e["t"] if d["first"] is None else min(d["first"], e["t"])
            d[key].add(other)
    for p in pair_out:
        srcs[p["src"]]["level"] = max(srcs[p["src"]]["level"], p["level"])
        sites[p["site"]]["level"] = max(sites[p["site"]]["level"], p["level"])
    ranked = sorted(srcs, key=lambda s: (-srcs[s]["level"], -len(srcs[s]["payloads"]), srcs[s]["first"] or 0, s))
    shown = set(ranked[:top_sources])

    def node_list(d, kind):
        return [{"id": k, "kind": kind, "payloads": len(v["payloads"]), "requests": v["requests"], "first": v["first"],
                 "level": v["level"], "links": len(v["sites" if kind == "src" else "sources"]),
                 "shown": kind == "site" or k in shown} for k, v in d.items()]

    data = {
        "title": title or "Attack map", "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "cats": cats, "levels": [{"name": n, "rule": r} for n, r in LEVELS], "series_min": SERIES_MIN,
        "phase_rank": PHASE_RANK, "sources": node_list(srcs, "src"), "sites": node_list(sites, "site"),
        "pairs": pair_out, "path_pairs": path_pairs,
        "paths": [{"site": s, "path": pth, "level": lv} for (s, pth), lv in sorted(path_level.items())],
        "points": point_out, "units": list(units.values()), "events": events,
        "hidden_sources": max(0, len(srcs) - len(shown)), "sanitized": bool(sanitize),
    }
    if sanitize:
        _sanitize(data)
    return data


def _sanitize(d):
    """Opaque labels for addresses and sites; payload texts removed."""
    ips = {s["id"]: f"src-{i + 1:03d}" for i, s in enumerate(sorted(d["sources"], key=lambda s: s["first"] or 0))}
    sites = {s["id"]: f"site-{i + 1:02d}" for i, s in enumerate(sorted(d["sites"], key=lambda s: s["first"] or 0))}
    for s in d["sources"]:
        s["id"] = ips[s["id"]]
    for s in d["sites"]:
        s["id"] = sites[s["id"]]
    for p in d["pairs"] + d["path_pairs"]:
        p["src"], p["site"] = ips[p["src"]], sites[p["site"]]
        p["points"] = []
        p["reasons"] = [r.split(" on ")[0] + " on one injection point" + (", complexity rising" if "rising" in r else "")
                        for r in p["reasons"]]
    paths = {}
    for p in d["paths"]:
        p["site"] = sites[p["site"]]
        p["path"] = paths.setdefault((p["site"], p["path"]), f"/path-{len(paths) + 1:03d}")
    for p in d["path_pairs"]:
        p["path"] = paths.get((p["site"], p["path"]), "/path")
    for e in d["events"]:
        site = sites.get(e["site"], "site")
        e["src"], e["site"], e["path"] = ips.get(e["src"], "src"), site, paths.get((site, e["path"]), "/path")
    for u in d["units"]:
        u.update(value="", summary="", site=sites.get(u["site"], "site"), path="", param="", ips=[])
    d["points"] = {}


def render(data, out):
    tpl = (HERE / "network_map_template.html").read_text(encoding="utf-8")
    blob = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    html = tpl.replace("__TITLE__", (data["title"] or "Attack map").replace("<", "&lt;")).replace("__DATA__", blob)
    tmp = Path(str(out) + ".tmp")
    tmp.write_text(html, encoding="utf-8")
    os.replace(tmp, out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("analysis")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--title")
    ap.add_argument("--top-sources", type=int, default=80, help="sources drawn individually (default 80)")
    ap.add_argument("--sanitize", action="store_true", help="opaque labels, no payload texts")
    ap.add_argument("--requests", help="requests.jsonl the analysis was made from, for sizes "
                                       "(default: beside the analysis, or its recorded source)")
    a = ap.parse_args()
    data = build(a.analysis, a.title, a.top_sources, a.sanitize, a.requests)
    render(data, a.output)
    lv = defaultdict(int)
    for p in data["pairs"]:
        lv[LEVELS[p["level"]][0]] += 1
    print(f"{len(data['sources'])} sources, {len(data['sites'])} sites, {len(data['units'])} attack payloads; "
          f"source/site pairs by level: {dict(lv)}; sizes: "
          f"{', '.join(k for k, v in data['sizes'].items() if v) or 'none'} -> {a.output}", file=sys.stderr)


if __name__ == "__main__":
    main()

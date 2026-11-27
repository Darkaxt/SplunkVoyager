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


MERGE_BUCKET_ROWS = int(os.environ.get("VOYAGER_MERGE_BUCKET_ROWS", 300_000))       # export rows per on-disk bucket when merging; bounds each worker's memory


def _new_group():
    return {"count": 0, "et": None, "lt": None, "src": set(), "status": set(), "action": set(),
            "req_bytes": 0, "req_n": 0, "resp_bytes": 0, "resp_n": 0, "resp_max": None}


def _key(r):
    return (str(r.get("site", "")), str(r.get("uri_path", "")), str(r.get("uri_query", "") or ""))


def _add(g, r):
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


def _write_groups(fh, groups):
    for (site, path, query), g in sorted(groups.items()):
        row = {"site": site, "uri_path": path, "uri_query": query, "count": g["count"],
               "et": _utc(g["et"]), "lt": _utc(g["lt"]), "src": sorted(g["src"]),
               "status": sorted(g["status"]), "action": sorted(g["action"])}
        if g["req_n"]:
            row.update(req_bytes=int(g["req_bytes"]), req_n=int(g["req_n"]))
        if g["resp_n"]:
            row.update(resp_bytes=int(g["resp_bytes"]), resp_n=int(g["resp_n"]), resp_max=int(g["resp_max"] or 0))
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def _rows(part):
    with part.open() as fh:
        for line in fh:
            if line.strip():
                r = json.loads(line)
                yield r.get("result", r) if isinstance(r, dict) else r


def _expected_rows(export_dir, files):
    try:
        man = json.loads((Path(export_dir) / "manifest.json").read_text(encoding="utf-8"))
        n = sum(int(w.get("records") or 0) for w in man.get("windows", []))
        if n:
            return n
    except (OSError, ValueError, TypeError):
        pass
    return sum(f.size for f in files) // 400 or 1          # rough: bytes per exported row


def _bucket_of(k, nb):
    import zlib
    return zlib.crc32("\t".join(k).encode("utf-8", "surrogatepass")) % nb


def _spread_parts(parts, bdir, nb, wid):
    """Pass 1 for one worker: stream its part files into its own bucket files, kept open for the whole pass,
    so memory stays small whatever the size of a part. Rows done so far go to w<id>.n for the progress log."""
    import gzip
    import time
    own = Path(bdir) / f"w{wid:02d}"
    own.mkdir(exist_ok=True)
    prog = Path(bdir) / f"w{wid:02d}.n"
    outs = [gzip.open(own / f"b{b:04d}.jsonl.gz", "wt", encoding="utf-8", compresslevel=1, newline="\n")
            for b in range(nb)]
    n, last = 0, time.time()
    try:
        for part in parts:
            with part.open() as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    r = json.loads(line)
                    outs[_bucket_of(_key(r.get("result", r) if isinstance(r, dict) else r), nb)].write(line + "\n")
                    n += 1
                    if not n & 0x3FFF and time.time() - last > 5:
                        last = time.time()
                        prog.write_text(str(n))
    finally:
        for o in outs:
            o.close()
    prog.write_text(str(n))
    return n


def _aggregate_bucket(bdir, b):
    """Pass 2 for one bucket: every request group is in it whole; written next to it, sorted."""
    import gzip
    groups = {}
    for bf in Path(bdir).glob(f"w*/b{b:04d}.jsonl.gz"):
        with gzip.open(bf, "rt", encoding="utf-8") as fh:
            for line in fh:
                r = json.loads(line)
                r = r.get("result", r) if isinstance(r, dict) else r
                k = _key(r)
                g = groups.get(k)
                if g is None:
                    g = groups[k] = _new_group()
                _add(g, r)
        bf.unlink()
    out = Path(bdir) / f"out-{b:04d}.jsonl"
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        _write_groups(fh, groups)
    return len(groups)


def merge(export_dir, out, log=None, bucket_rows=MERGE_BUCKET_ROWS, workers=None):
    """
    One row per site + path + query string over all export windows.

    Memory stays bounded however large the export: when it has more than bucket_rows rows, pass 1 spreads the
    rows over on-disk buckets (gzip, beside the output) by a hash of site + path + query string, so every
    request group lands whole in one bucket; pass 2 aggregates one bucket at a time. Both passes run in
    `workers` processes (default: cores - 1, at most 4). Progress is logged as it goes.
    """
    import exportfiles
    import shutil
    import time
    from concurrent.futures import ProcessPoolExecutor, as_completed
    log = log or (lambda m: print(m, file=sys.stderr, flush=True))
    files = exportfiles.parts(export_dir, "jsonl")
    if not files:
        raise SystemExit(f"No part files (part-*.jsonl, part-*.jsonl.zip or export.zip) in {export_dir}")
    out = Path(out)
    tmp = Path(str(out) + ".tmp")
    expected = _expected_rows(export_dir, files)
    nb = max(1, -(-expected // bucket_rows))
    workers = workers or max(1, min(4, (os.cpu_count() or 2) - 1))
    t0, rows = time.time(), 0

    def eta(done, total, since):
        el = time.time() - since
        return f", about {el / done * (total - done) / 60:,.0f} min left" if done and el / done * (total - done) >= 60 else ""

    if nb == 1:
        groups, last = {}, 0.0
        for i, f in enumerate(files, 1):
            for r in _rows(f):
                rows += 1
                k = _key(r)
                g = groups.get(k)
                if g is None:
                    g = groups[k] = _new_group()
                _add(g, r)
            if time.time() - last >= 30 or i == len(files):
                last = time.time()
                log(f"Merge: part {i}/{len(files)}, {rows:,} rows{eta(i, len(files), t0)}")
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            _write_groups(fh, groups)
        n_groups = len(groups)
    else:
        bdir = out.with_name(out.name + ".buckets")
        shutil.rmtree(bdir, ignore_errors=True)
        bdir.mkdir(parents=True)
        log(f"Merge: {expected:,} rows expected in {len(files)} parts; {nb} buckets in {bdir}, {workers} processes. "
            f"Pass 1 of 2: spreading the rows")
        try:
            last = time.time()
            import multiprocessing     # spawn everywhere: what runs on Windows is what is tested on Linux
            from concurrent.futures import wait
            # parts shared out by size (largest first, to the least loaded worker), one task per worker
            loads, shares = [0] * workers, [[] for _ in range(workers)]
            for f in sorted(files, key=lambda f: -f.size):
                w = loads.index(min(loads))
                shares[w].append(f)
                loads[w] += f.size
            with ProcessPoolExecutor(max_workers=workers, mp_context=multiprocessing.get_context("spawn")) as ex:
                futs = [ex.submit(_spread_parts, sh, str(bdir), nb, w) for w, sh in enumerate(shares) if sh]
                while True:
                    done, pending = wait(futs, timeout=30)
                    for fu in done:
                        fu.result()                    # a worker's error stops the merge here
                    rows = 0
                    for pf in bdir.glob("w*.n"):
                        try:
                            rows += int(pf.read_text() or 0)
                        except (OSError, ValueError):
                            pass
                    el = time.time() - t0
                    left = el / rows * (expected - rows) if rows else 0
                    log(f"Merge pass 1: {rows:,}/{expected:,} rows ({rows / max(el, 1):,.0f}/s)"
                        + (f", about {left / 60:,.0f} min left" if rows and left >= 60 and pending else ""))
                    if not pending:
                        break
                rows = sum(fu.result() for fu in futs)
                size = sum(p.stat().st_size for p in bdir.rglob("*.gz"))
                log(f"Merge pass 1 done: {rows:,} rows, {size / 1e9:,.1f} GB of buckets. Pass 2 of 2: aggregating")
                n_groups, t1, last = 0, time.time(), time.time()
                with open(tmp, "wb") as fh:
                    for b, n in enumerate(ex.map(_aggregate_bucket, [str(bdir)] * nb, range(nb)), 1):
                        part = bdir / f"out-{b - 1:04d}.jsonl"
                        with open(part, "rb") as src:
                            shutil.copyfileobj(src, fh, 1 << 20)
                        part.unlink()
                        n_groups += n
                        if time.time() - last >= 30 or b == nb:
                            last = time.time()
                            log(f"Merge pass 2: {b}/{nb} buckets, {n_groups:,} request groups{eta(b, nb, t1)}")
        finally:
            shutil.rmtree(bdir, ignore_errors=True)
    os.replace(tmp, out)
    log(f"{rows:,} rows from the export windows -> {n_groups:,} request groups in {out} "
        f"({out.stat().st_size / 1e9:,.2f} GB, {(time.time() - t0) / 60:,.1f} min)")


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
                              "categories": sorted(v["categories"]), **_masked_display(k)} for k, v in cb.items()),
                            key=lambda x: (x["internal"], -x["units"], x["value"])),
        "targets": sorted(({"site": k, "requests": v["requests"], "paths": len(v["paths"]),
                            "categories": sorted(v["categories"])} for k, v in tg.items()),
                          key=lambda x: (-x["requests"], x["site"])),
        "categories": (d.get("meta") or {}).get("effective_category_counts") or (d.get("meta") or {}).get("category_counts"),
    }
    # credentials in the request URLs: full values in credentials.jsonl, masked in findings.json, masked and
    # encoded (decoded on click) in the HTML report
    reqs = _requests_for(analysis_path, d)
    if reqs:
        import credentials
        creds = credentials.scan_requests(reqs)
        credentials.write_jsonl(creds, Path(out).with_name("credentials.jsonl"))
        res["credentials"] = credentials.summary(creds, src.keys())
        report = Path(analysis_path).with_name("report.html")
        if report.is_file():
            credentials.inject_report(report, creds, src.keys())
            print(f"Credentials section added to {report}", file=sys.stderr)
    Path(out).write_text(json.dumps(res, indent=1), encoding="utf-8")
    print(f"{len(res['sources'])} attack sources, {len(res['callbacks'])} callback artifacts, "
          f"{len(res['targets'])} targeted sites"
          + (f", {len(res['credentials'])} credential(s) in URLs" if "credentials" in res else "") + f" -> {out}",
          file=sys.stderr)


def _masked_display(value):
    """{"display": value with the password of any user:password@ masked} when it has one."""
    import credentials
    out = credentials.USERINFO.sub(lambda m: m.group(0)[:m.start(3) - m.start(0)]
                                   + credentials.mask(credentials.decode(m.group(3), plus=False)) + "@" + m.group(4), value)
    return {"display": out} if out != value else {}


def _requests_for(analysis_path, report):
    """The merged requests an analysis was made from: beside it, or its recorded source."""
    for c in (Path(analysis_path).with_name("requests.jsonl"), Path((report.get("meta") or {}).get("source") or "")):
        if c.name and c.suffix == ".jsonl" and c.is_file():
            return c
    return None


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

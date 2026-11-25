#!/usr/bin/env python3
"""
pivot_graph.py - IOC pivot graph with an animated timeline, built from Splunk exports.

  1. seed    Stage 1 in Splunk: hourly counts of an IOC by index/sourcetype (cheap), then
             raw pulls (_time, _raw, host only) for every index/sourcetype under a size
             threshold. Both run through splunk_export.py: resumable, sleep-proof.
  2. build   Everything else on the laptop: entity extraction (IPs, URLs, domains, emails,
             accounts, hosts), binning, graph, one self-contained HTML file.
  3. status  What a case folder holds.

Expanding a node = seeding the case again with that entity.

Examples
  python pivot_graph.py seed cases\\acct "<ACCOUNT>" --earliest 2026-10-15 --latest 2026-11-16
  python pivot_graph.py build cases\\acct -o cases\\acct\\graph.html
  python pivot_graph.py seed cases\\acct "10.1.2.3" --earliest 2026-10-20 --latest 2026-10-23
  python pivot_graph.py build cases\\acct --sanitize -o graph_shareable.html
"""
import argparse
import csv
import importlib.util
import glob
import hashlib
import time
import html
import json
import math
import os
import shutil
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, quote_plus, unquote, unquote_plus, urlparse

HERE = Path(__file__).resolve().parent
try:  # shared with the Voyager web app (data/settings.json)
    sys.path.insert(0, str(HERE))
    import voyager_settings as _vs
    SETTINGS = _vs.load()
except Exception:
    SETTINGS = {"splunk_base": os.environ.get("SPLUNK_BASE", ""), "splunk_locale": os.environ.get("SPLUNK_LOCALE", "en-US"),
                "splunk_app": os.environ.get("SPLUNK_APP", "")}
EXPORTER = HERE / "splunk_export.py"
BIN = 3600  # base bin: 1 hour

csv.field_size_limit(min(sys.maxsize, 2 ** 31 - 1))


# =========================================================================== helpers
def slug(s, n=60):
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", str(s)).strip("_")
    return (s[:n] or "x")


def spl_quote(s):
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


def to_epoch(v):
    if v is None or v == "":
        return None
    s = str(v).strip()
    if re.fullmatch(r"\d{9,11}(\.\d+)?", s):
        return float(s)
    s = re.sub(r"(\.\d{6})\d+", r"\1", s).replace("Z", "+00:00")
    m = re.match(r"(.*[+-]\d\d)(\d\d)$", s)          # +0000 -> +00:00
    if m and ":" not in s[-6:]:
        s = f"{m.group(1)}:{m.group(2)}"
    try:
        d = datetime.fromisoformat(s)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.astimezone()
    return d.timestamp()


def variants(s):
    """Encodings of an IOC to search together: as given, URL-decoded, URL-/form-/double-encoded."""
    out, seen = [], set()

    def add(label, v):
        if v and v.lower() not in seen:
            seen.add(v.lower())
            out.append((label, v))
    add("as given", s)
    base = unquote(s)
    add("url-decoded", base)
    if "+" in s:
        add("form-decoded", unquote_plus(s))
    add("url-encoded", quote(base, safe=""))
    add("form-encoded", quote_plus(base, safe=""))
    add("url-encoded (lenient)", quote(base, safe="!$'()*,;:=&+~"))
    add("double-encoded", quote(quote(base, safe=""), safe=""))
    return out


def mask_all(text, secrets):
    """Replace every variant of every secret (case-insensitive) with <SECRET>."""
    for sec in secrets:
        for _, v in sorted(variants(sec), key=lambda x: -len(x[1])):
            text = re.sub(re.escape(v), "<SECRET>", text, flags=re.I)
    return text


_EXP = None


def exporter(args):
    """Load splunk_export.py in-process (the query, which may hold a secret, never goes on a command line)."""
    global _EXP
    if _EXP:
        return _EXP
    spec = importlib.util.spec_from_file_location("splunk_export", args.exporter)
    se = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(se)
    base = args.base or se.DEFAULT_BASE
    host = urlparse(base).hostname
    sp = se.Splunk(base, getattr(args, "locale", None) or se.DEFAULT_LOCALE, lambda quiet: se.find_cookies(args.cookies, args.db, host, quiet))
    while True:
        try:
            user, _ = sp.whoami()
            break
        except se.AuthError as e:
            sp.reauth_wait(str(e))
    se.log(f"Authenticated as {user}")
    _EXP = (se, sp)
    return _EXP


def case_load(case_dir):
    p = Path(case_dir) / "case.json"
    if p.is_file():
        return json.loads(p.read_text(encoding="utf-8"))
    return {"created": datetime.now().isoformat(timespec="seconds"), "seeds": []}


def case_save(case_dir, case):
    Path(case_dir).mkdir(parents=True, exist_ok=True)
    p = Path(case_dir) / "case.json"
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(case, indent=2), encoding="utf-8")
    os.replace(tmp, p)


def run_export(args, query, out_dir, earliest, latest, chunk, fmt, masks=(), windows=None):
    shown = mask_all(query, masks) if masks else query
    print(f"\n>>> export -> {out_dir}\n    {shown[:300]}", flush=True)
    if args.dry_run:
        return 0
    se, sp = exporter(args)
    ns = argparse.Namespace(query=query, out_dir=str(out_dir), earliest=earliest, latest=latest, chunk=chunk,
                            format=fmt, app=args.app, max_jobs=args.max_jobs, max_attempts=4,
                            accept_incomplete=False, retry_failed=False, keep_jobs=False, merge=False,
                            page_size=se.PAGE_SIZE, poll=int(args.poll or 15), job_ttl=3 * 86400,
                            search_level="fast", mask=[v for sec in masks for _, v in variants(sec)],
                            windows=windows)
    try:
        se.run(ns, sp)
        return 0
    except SystemExit as e:
        if isinstance(e.code, int) or e.code is None:
            return e.code or 0
        print(f"    export stopped: {e.code}", flush=True)
        return 1


def active_ranges(bins, gap_hours=1):
    """Merge the hours that had hits into [start, end) ranges; gaps up to gap_hours are bridged."""
    hours = sorted(b for b, c in bins.items() if c > 0)
    ranges = []
    for h in hours:
        if ranges and h - ranges[-1][1] <= gap_hours * BIN:
            ranges[-1][1] = h + BIN
        else:
            ranges.append([h, h + BIN])
    return [tuple(r) for r in ranges]


def read_parts(folder, kind):
    files = sorted(glob.glob(os.path.join(folder, f"part-*.{kind}")))
    for f in files:
        if os.path.getsize(f) == 0:
            continue
        if kind == "csv":
            with open(f, encoding="utf-8-sig", newline="") as fh:
                yield from csv.DictReader(fh)
        else:
            with open(f, encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        yield json.loads(line)


def read_parts_ref(folder):
    """Like read_parts(jsonl) but yields (file, line number, event) so samples can be kept as pointers."""
    for f in sorted(glob.glob(os.path.join(folder, "part-*.jsonl"))):
        if os.path.getsize(f) == 0:
            continue
        with open(f, encoding="utf-8") as fh:
            for i, line in enumerate(fh):
                if line.strip():
                    yield f, i, json.loads(line)


def stage1_nodes(stage_dir):
    """{(index, sourcetype): {'count': n, 'bins': {bin_epoch: n}}} from the stage-1 run."""
    nodes = {}
    for row in read_parts(stage_dir, "csv"):
        idx, st = row.get("index", ""), row.get("sourcetype", "")
        t = to_epoch(row.get("_time"))
        try:
            n = int(float(row.get("count") or 0))
        except ValueError:
            continue
        if t is None:
            continue
        b = int(t // BIN * BIN)
        d = nodes.setdefault((idx, st), {"count": 0, "bins": defaultdict(int)})
        d["count"] += n
        d["bins"][b] += n
    return nodes


# =========================================================================== seed
def cmd_seed(args):
    case = case_load(args.case)
    ioc = args.ioc.strip()
    sd = next((s for s in case["seeds"] if s["value"] == ioc), None)
    if sd is None:
        sd = {"value": ioc, "slug": f"{len(case['seeds']) + 1:02d}_{slug(ioc, 40)}",
              "earliest": args.earliest, "latest": args.latest, "added": datetime.now().isoformat(timespec="seconds")}
        case["seeds"].append(sd)
        case_save(args.case, case)
    if (args.earliest, args.latest) != (sd["earliest"], sd["latest"]):
        if getattr(args, "reset_range", False):
            # throw away this seed's results (stage 1 and raw pulls) and search again with the new range
            shutil.rmtree(Path(args.case) / "seeds" / sd["slug"], ignore_errors=True)
            sd.update(earliest=args.earliest, latest=args.latest)
            sd.pop("variants", None)
            case_save(args.case, case)
            print(f"Range of {ioc!r} reset to {args.earliest} -> {args.latest}; its earlier results were removed.",
                  file=sys.stderr)
        else:
            print(f"\n*** {ioc!r} is already in this case with the range {sd['earliest']} -> {sd['latest']}.\n"
                  f"*** Continuing with THAT range, not {args.earliest} -> {args.latest}.\n"
                  f"*** To search the new range, add --reset-range (redoes this value only) or use a new case folder.\n",
                  file=sys.stderr)
    legacy = "variants" not in sd and (Path(args.case) / "seeds" / sd["slug"] / "stage1").is_dir()
    if legacy:
        print("This seed was started by an earlier version: keeping its original search (IOC as given) so it resumes.")
    var = [("as given", ioc)] if (args.no_variants or legacy) else list(variants(ioc))
    sd["variants"] = [l for l, _ in var]
    case_save(args.case, case)
    print("Searching " + ", ".join(l for l, _ in var) + f" ({len(var)} form(s))")
    if any("*" in v for _, v in var):
        print("  NOTE: '*' is a wildcard in Splunk searches, even in quotes; results may include extra matches.")
    # one form: plain quoted term, exactly as earlier versions wrote it, so existing case folders resume
    terms = spl_quote(var[0][1]) if len(var) == 1 else "(" + " OR ".join(spl_quote(v) for _, v in var) + ")"
    masks = []
    seed_dir = Path(args.case) / "seeds" / sd["slug"]

    # ---- stage 1
    base = args.base_search or "index=*"
    q1 = f"{base} {terms} | bin _time span=1h | stats count by index sourcetype _time"
    rc = run_export(args, q1, seed_dir / "stage1", sd["earliest"], sd["latest"], args.chunk_stage1, "csv", masks)
    if rc != 0:
        sys.exit(f"Stage 1 did not finish (exit {rc}). Rerun the same command to resume.")
    if args.dry_run:
        return
    nodes = stage1_nodes(seed_dir / "stage1")
    if not nodes:
        print("\nStage 1 found no events for this IOC in the range.")
        return

    # ---- plan raw pulls
    print(f"\nStage 1: {sum(d['count'] for d in nodes.values()):,} events in {len(nodes)} index/sourcetype node(s)\n")
    plan = []
    for (idx, st), d in sorted(nodes.items(), key=lambda kv: kv[1]["count"]):
        forced = any(f.lower() in f"{idx}/{st}".lower() for f in args.include)
        take = (d["count"] <= args.max_events or forced) and not args.stage1_only
        plan.append((idx, st, d["count"], take, d["bins"]))
        print(f"  {'PULL ' if take else 'skip '} {d['count']:>12,}  {idx} / {st}")
    big = [p for p in plan if not p[3] and not args.stage1_only]
    if big:
        print(f"\n  {len(big)} node(s) over --max-events {args.max_events:,} are shown in the graph with their counts "
              f"and timeline only. Force one with --include \"<index>/<sourcetype>\" (or narrow the range).")

    failed = 0
    for idx, st, n, take, bins in plan:
        if not take:
            continue
        rngs = active_ranges(bins, args.gap_hours)
        hours = sum((b - a) // BIN for a, b in rngs)
        print(f"    {idx}/{st}: {len(rngs)} active range(s), {hours} hour(s) "
              f"of {len(bins) and (max(bins) - min(bins)) // BIN + 1} between first and last hit")
        q2 = (f"index={spl_quote(idx)} sourcetype={spl_quote(st)} {terms} "
              f"| fields _time _raw index sourcetype host | fields - _bkt _cd _si _serial _indextime _sourcetype _subsecond")
        out = seed_dir / "raw" / slug(f"{idx}__{st}", 90)
        rc = run_export(args, q2, out, sd["earliest"], sd["latest"], args.chunk_raw, "jsonl", masks, windows=rngs)
        if rc != 0:
            failed += 1
            print(f"  !! raw pull for {idx}/{st} did not finish (exit {rc}); rerun to resume")
        else:
            meta = out / "node.json"
            meta.write_text(json.dumps({"index": idx, "sourcetype": st}), encoding="utf-8")
    print(f"\nDone{' with ' + str(failed) + ' unfinished pull(s)' if failed else ''}. Build the graph with:\n"
          f"  python pivot_graph.py build {args.case}")
    if failed:
        sys.exit(1)


# =========================================================================== extraction
TLDS = set("""com net org int edu gov mil eu info biz name pro io co ai app dev cloud online site xyz top club
tech store shop live news me tv cc ws su onion int arpa
ac ad ae af ag al am ao ar at au az ba bd be bf bg bh bi bj bn bo br bs bt bw by bz ca cd cf cg ch ci cl cm cn
cr cu cv cy cz de dj dk dm do dz ec ee eg er es et fi fj fm fr ga gd ge gh gi gl gm gn gr gt gu gy hk hn hr ht
hu id ie il im in iq ir is it je jm jo jp ke kg kh kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc mk ml mm
mn mo mr mt mu mv mw mx my mz na ne ng ni nl no np nz om pa pe pg ph pk pl pr ps pt py qa ro rs ru rw sa sc sd
se sg si sk sl sm sn so sr st sv sy sz tg th tj tk tl tm tn to tr tt tw tz ua ug uk us uy uz va vc ve vn ye za
zm zw""".split())
# file extensions that are also TLDs: "main.py", "run.sh", "README.md", "x.pl"... are files, not domains
FILE_LIKE_TLDS = {"py", "sh", "md", "pl", "rs", "cs", "so", "ps", "sc", "gz", "zip", "mov", "jar"}

RE_URL = re.compile(r"\b(?:https?|t3s?|ldaps?|ftps?|sftp|smb)://[^\s\"'<>()\[\]{}|\\^`]+", re.I)
RE_USERINFO = re.compile(r"(\b[a-z][a-z0-9+.-]*://)([^/\s\"'<>]+)@", re.I)  # greedy: up to the LAST @ (passwords may contain @)
RE_SECRETS = re.compile(r"(?i)\b(password|passwd|pwd|pass|secret|token|apikey|api_key|authorization)(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&\"'}]+)")
RE_IP = re.compile(r"(?<![\w.#-])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\w.]*\d)(?!\.\w)")
RE_EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}(?![\w-])")
RE_DOMAIN = re.compile(r"(?<![\w@.-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,24}))(?![\w-])")
RE_UNC = re.compile(r"\\\\([A-Za-z0-9][\w.-]{0,253})\\")
RE_ACCOUNT = re.compile(
    r"(?i)(?<![\w-])(?:user(?:_?name)?|uid|userid|login|account(?:_?name)?|TargetUserName|SubjectUserName|"
    r"src_user|WL_USERNAME|node-manager-username)[\"']?\s*(?:=|:|>)\s*[\"']?([A-Za-z0-9._@$\\-]{2,64})")
RE_ACCOUNT2 = re.compile(r"(?i)\b(?:with userid|requested by|password for|USER|nmConnect)\s+([A-Za-z0-9._@$\\-]{2,64})")
RE_SFTP = re.compile(r"\[(?:SFTP|FTPS?|HTTPS?):[^:\]]+:([^:\]]+):[^\]]*\]")
NOT_ACCOUNTS = {"-", "null", "none", "n/a", "unknown", "true", "false", "anonymous", "the", "a", "is"}
STACK_LINE = re.compile(r"^\s*(?:at\s+[\w$.]+\(|\.\.\.\s*\d+\s+more|Caused by:)")


def redact(text):
    text = RE_USERINFO.sub(r"\1REDACTED@", text)
    return RE_SECRETS.sub(lambda m: f"{m.group(1)}{m.group(2)}REDACTED", text)


def valid_ip(ip):
    if ip in ("0.0.0.0", "255.255.255.255") or ip.startswith("127."):
        return False
    return True


def domain_ok(full, tld, text, end):
    tld = tld.lower()
    if tld not in TLDS:
        return False
    labels = full.split(".")
    if len(labels) == 2 and tld in FILE_LIKE_TLDS:
        return False
    if all(l.isdigit() for l in labels[:-1]):
        return False
    # longer dotted identifier (Java package, class name) continues after the TLD
    if end < len(text) - 1 and text[end] == "." and text[end + 1].isalnum():
        return False
    # Class-like: a label starting with an uppercase letter followed by lowercase (HttpURLConnection, Tomcat9)
    if any(re.match(r"[A-Z][a-z]", l) for l in labels):
        return False
    return True


def extract(raw, host_field=None):
    """Return set of (type, value) found in one redacted event."""
    ents = set()
    lines = [ln for ln in raw.splitlines() if not STACK_LINE.match(ln)]
    text = "\n".join(lines)
    for m in RE_URL.finditer(text):
        u = m.group(0).rstrip(".,;:'\")]}>")
        ents.add(("url", u))
        hm = re.match(r"\w+://(?:[^@/]*@)?([^/:?#]+)", u, re.I)
        if hm:
            h = hm.group(1)
            if RE_IP.fullmatch(h):
                if valid_ip(h):
                    ents.add(("ip", h))
            elif "." in h:
                ents.add(("domain", h.lower()))
            else:
                ents.add(("host", h.lower()))
    text_nourl = RE_URL.sub(" ", text)
    for m in RE_EMAIL.finditer(text_nourl):
        ents.add(("email", m.group(0).lower()))
    text_noemail = RE_EMAIL.sub(" ", text_nourl)
    for m in RE_IP.finditer(text_noemail):
        if valid_ip(m.group(0)):
            ents.add(("ip", m.group(0)))
    for m in RE_DOMAIN.finditer(text_noemail):
        full, tld = m.group(1), m.group(2)
        if RE_IP.fullmatch(full):
            continue
        if domain_ok(full, tld, text_noemail, m.end(1)):
            ents.add(("domain", full.lower()))
    for m in RE_UNC.finditer(text):
        h = m.group(1)
        if RE_IP.fullmatch(h):
            ents.add(("ip", h))
        else:
            ents.add(("host", h.lower()))
    for rx in (RE_ACCOUNT, RE_ACCOUNT2, RE_SFTP):
        for m in rx.finditer(text):
            v = m.group(1).strip(".,;:'\"")
            if v.lower() in NOT_ACCOUNTS or len(v) < 2 or v.isdigit() or "REDACTED" in v:
                continue
            ents.add(("account", v.lower()))
    if host_field:
        ents.add(("host", str(host_field).lower()))
    return ents


# =========================================================================== build
def cmd_build(args):
    # one or more case folders; seeds with the same value in several cases are kept once (first case wins)
    seed_list = []          # (case_dir, seed dict)
    seen_vals = {}
    for cdir in args.case:
        c = case_load(cdir)
        for sd in c["seeds"]:
            lv = sd["value"].lower()
            if lv in seen_vals:
                print(f"note: seed {sd['value']!r} is in both {seen_vals[lv]} and {cdir}; using {seen_vals[lv]}",
                      file=sys.stderr)
                continue
            seen_vals[lv] = cdir
            seed_list.append((cdir, sd))
    if not seed_list:
        sys.exit(f"No seeds in {', '.join(args.case)}. Run `seed` first.")
    case = {"seeds": [sd for _, sd in seed_list]}
    group = args.group
    bin_s = args.bin * 60
    if bin_s not in (60, 300, 900, 3600):
        sys.exit("--bin must be 1, 5, 15 or 60 (minutes)")

    def src_id(idx, st):
        """Source node for an index/sourcetype pair, per --group."""
        if group == "sourcetype":
            return f"st:{st}", st
        if group == "index":
            return f"ix:{idx}", idx
        return f"st:{idx}/{st}", f"{idx} · {st}"

    # sources pulled by more than one seed: only those need per-event dedup (keeps memory flat otherwise)
    pulls = defaultdict(set)
    raw_metas = []
    for cdir, sd in seed_list:
        for meta in glob.glob(str(Path(cdir) / "seeds" / sd["slug"] / "raw" / "*" / "node.json")):
            m = json.loads(Path(meta).read_text(encoding="utf-8"))
            pulls[src_id(m["index"], m["sourcetype"])[0]].add(sd["value"])
            raw_metas.append(meta)
    shared = {k for k, v in pulls.items() if len(v) > 1}
    total_bytes = sum(os.path.getsize(f) for meta in raw_metas
                      for f in glob.glob(os.path.join(os.path.dirname(meta), "part-*.jsonl")))
    print(f"Reading {len(raw_metas)} raw source folder(s), {total_bytes / 1e9:.2f} GB of events", file=sys.stderr)
    t_start, done_bytes, src_i = time.time(), 0, 0
    # long tail: entities too rare in a source to ever be drawn or listed get only a compact counter
    tail = {}            # key -> [count, first, last, source bitmask]
    tail_src = []        # source labels, index = bit
    full_per_src = max(args.max_entities, args.table_limit)
    seen_ev = defaultdict(set)    # source node id -> event hashes already counted (event pulled by several seeds)
    co_seen = defaultdict(set)    # (seed key a, seed key b) -> event hashes
    nodes = {}      # id -> node
    edges = {}      # (a, b) -> edge
    samples = defaultdict(list)

    def node(nid, **kw):
        n = nodes.get(nid)
        if n is None:
            n = nodes[nid] = {"id": nid, "count": 0, "first": None, "last": None, "seeds": set(), **kw}
        return n

    def touch(n, t, c=1):
        n["count"] += c
        n["first"] = t if n["first"] is None else min(n["first"], t)
        n["last"] = t if n["last"] is None else max(n["last"], t)

    def edge(a, b, kind):
        e = edges.get((a, b))
        if e is None:
            e = edges[(a, b)] = {"s": a, "t": b, "kind": kind, "bins": defaultdict(int), "count": 0}
        return e

    seed_keys = {}
    seed_terms = {}
    for sd in case["seeds"]:
        v = sd["value"]
        k = ent_key_for_seed(v)
        seed_terms[v] = variants(v)
        for _, var in seed_terms[v]:
            seed_keys[var.lower()] = k
        seed_keys[v.lower()] = k
    for cdir, sd in seed_list:
        seed_dir = Path(cdir) / "seeds" / sd["slug"]
        sk = seed_keys[sd["value"].lower()]
        sn = node(sk, type=sk.split(":", 1)[0], label=sd["value"], seed=True)
        sn["seed"] = True
        st_nodes = stage1_nodes(seed_dir / "stage1")
        print(f"seed {sd['value']!r}: {len(st_nodes)} index/sourcetype pair(s) -> "
              f"{len({src_id(i, t)[0] for i, t in st_nodes})} source node(s) (--group {group})", file=sys.stderr)
        for (idx, st), d in st_nodes.items():
            nid, lbl = src_id(idx, st)
            n = node(nid, type="source", label=lbl, by_index={}, by_st={})
            n["by_index"][idx] = n["by_index"].get(idx, 0) + d["count"]
            n["by_st"][st] = n["by_st"].get(st, 0) + d["count"]
            n["seeds"].add(sd["value"])
            edge(sk, nid, "seed")      # bins and first/last filled after the raw pulls (exact when pulled)
            n["stage1"] = n.get("stage1", 0) + d["count"]
        # raw pulls
        raw_bins = {}       # (index, sourcetype) -> {fine bin: events of this seed}
        raw_span = {}       # (index, sourcetype) -> [exact first, exact last] event time
        lterms = [(lbl, var.lower()) for lbl, var in seed_terms[sd["value"]]]
        others = [(ov, [v.lower() for _, v in ot]) for ov, ot in seed_terms.items() if ov != sd["value"]]
        for meta in sorted(glob.glob(str(seed_dir / "raw" / "*" / "node.json"))):
            m = json.loads(Path(meta).read_text(encoding="utf-8"))
            nid, lbl = src_id(m["index"], m["sourcetype"])
            src_i += 1
            folder = os.path.dirname(meta)
            sbytes = sum(os.path.getsize(f) for f in glob.glob(os.path.join(folder, "part-*.jsonl")))
            t_src, last_tick = time.time(), time.time()
            print(f"[{src_i}/{len(raw_metas)}] {m['index']} · {m['sourcetype']}  ({sbytes / 1e6:,.0f} MB)",
                  file=sys.stderr, flush=True)
            n = node(nid, type="source", label=lbl, by_index={}, by_st={})
            n["pulled"] = True
            nev = 0
            per_ent = {}   # key -> [count, tmin, tmax, type, label, {bin: n}]
            dedup = nid in shared
            nread = 0
            rb = raw_bins.setdefault((m["index"], m["sourcetype"]), defaultdict(int))
            rt = raw_span.setdefault((m["index"], m["sourcetype"]), [None, None])
            for fpath, lineno, ev in read_parts_ref(folder):
                nread += 1
                if not nread % 20000 and time.time() - last_tick > 15:
                    last_tick = time.time()
                    print(f"      {nread:,} events, {len(per_ent):,} entities, "
                          f"{nread / (last_tick - t_src):,.0f} ev/s", file=sys.stderr, flush=True)
                t = to_epoch(ev.get("_time"))
                raw = ev.get("_raw")
                if t is None or not raw:
                    continue
                rb[int(t // bin_s * bin_s)] += 1
                if rt[0] is None or t < rt[0]: rt[0] = t
                if rt[1] is None or t > rt[1]: rt[1] = t
                raw = raw if isinstance(raw, str) else json.dumps(raw)
                low = raw.lower()
                vc = n.setdefault("variants", {})
                for lbl, var in lterms:
                    if var in low:
                        vc[lbl] = vc.get(lbl, 0) + 1
                h = None
                # direct seed <-> seed link: the event also contains another seed (any form)
                rraw = None
                for ov, oterms in others:
                    if not any(var in low for var in oterms):
                        continue
                    h = h or hashlib.sha1(f"{t}|{raw}".encode("utf-8", "replace")).digest()[:12]
                    ok = seed_keys[ov.lower()]
                    pair = tuple(sorted((sk, ok)))
                    if h in co_seen[pair]:
                        continue
                    co_seen[pair].add(h)
                    e = edge(pair[0], pair[1], "cooccur")
                    e["bins"][int(t // bin_s * bin_s)] += 1
                    e["count"] += 1
                    e["first"] = t if "first" not in e else min(e["first"], t)
                    e["last"] = max(e.get("last", t), t)
                    if len(samples[pair]) < 5:
                        rraw = rraw or (raw if args.no_redact else redact(raw))
                        samples[pair].append({"t": t, "raw": rraw[:600], "src": n["label"]})
                if dedup:               # same source pulled by another seed: count each event once
                    h = h or hashlib.sha1(f"{t}|{raw}".encode("utf-8", "replace")).digest()[:12]
                    if h in seen_ev[nid]:
                        continue
                    seen_ev[nid].add(h)
                nev += 1
                raw = rraw or (raw if args.no_redact else redact(raw))
                b = int(t // bin_s * bin_s)
                ref = None
                for typ, val in sorted(extract(raw, ev.get("host"))):
                    k = seed_keys.get(val.lower(), f"{typ}:{val.lower()}")   # value of any seed -> that seed's node
                    if k == sk:
                        continue
                    pe = per_ent.get(k)
                    if pe is None:
                        tv = (nodes[k]["type"], nodes[k]["label"]) if k in nodes and nodes[k].get("seed") else (typ, val)
                        pe = per_ent[k] = [0, t, t, tv[0], tv[1], {}]
                    pe[0] += 1
                    if t < pe[1]: pe[1] = t
                    if t > pe[2]: pe[2] = t
                    pe[5][b] = pe[5].get(b, 0) + 1
                    sl = samples[(nid, k)]
                    if len(sl) < 3:
                        # keep a pointer, not the text: read back only for entities that reach the HTML
                        ref = ref or (fpath, lineno, t)
                        sl.append(ref)
            n["raw_events"] = n.get("raw_events", 0) + nev
            for fld, v in (("by_index", m["index"]), ("by_st", m["sourcetype"])):
                if not n[fld].get(v):           # no stage-1 count for it: use the pulled events
                    n[fld][v] = n[fld].get(v, 0) + nev
            done_bytes += sbytes
            el = time.time() - t_start
            eta = el / done_bytes * (total_bytes - done_bytes) if done_bytes else 0
            print(f"      {nev:,} events, {len(per_ent):,} entities in {time.time() - t_src:,.0f}s"
                  f"  | overall {done_bytes / max(total_bytes, 1):.0%}, ~{eta / 60:,.0f} min left",
                  file=sys.stderr, flush=True)
            ranked = sorted(per_ent, key=lambda k: -per_ent[k][0])
            if len(ranked) > full_per_src:
                if n["label"] not in tail_src:
                    tail_src.append(n["label"])
                bit = 1 << tail_src.index(n["label"])
                for k in ranked[full_per_src:]:
                    if k in nodes:
                        continue            # already a full node from another source: keep it complete
                    cnt, tmin, tmax = per_ent[k][:3]
                    tr = tail.get(k)
                    if tr is None:
                        tail[k] = [cnt, tmin, tmax, bit]
                    else:
                        tr[0] += cnt; tr[1] = min(tr[1], tmin); tr[2] = max(tr[2], tmax); tr[3] |= bit
                    samples.pop((nid, k), None)
                    del per_ent[k]
            for k, (cnt, tmin, tmax, typ, lbl, bins) in per_ent.items():
                en = node(k, type=typ, label=lbl)
                en["seeds"].add(sd["value"])
                e = edge(nid, k, "entity")
                for b, c in bins.items():
                    e["bins"][b] += c
                e["count"] += cnt
                touch(en, tmin, cnt)
                touch(en, tmax, 0)
                e["first"] = tmin if "first" not in e else min(e["first"], tmin)
                e["share"] = max(e.get("share", 0), cnt / max(nev, 1))
            per_ent = None
        # seed -> source activity: exact (from the pulled events) where pulled, hourly stage-1 counts otherwise
        for (idx, st), d in st_nodes.items():
            nid, _ = src_id(idx, st)
            e = edge(sk, nid, "seed")
            rb = raw_bins.get((idx, st))
            if rb:
                for b, c in rb.items():
                    e["bins"][b] += c
                    e["count"] += c
                t0, t1 = raw_span[(idx, st)]
            else:
                for b, c in d["bins"].items():
                    e["bins"][b] += c
                    e["count"] += c
                t0, t1 = min(d["bins"]), max(d["bins"]) + BIN - 1
                if bin_s < BIN:
                    nodes[nid]["coarse"] = True
            for n_ in (nodes[nid], sn):
                touch(n_, t0, 0)
                touch(n_, t1, 0)

    # merge seed nodes that are also entities (expansions) - same key, nothing to do; mark infra
    src_nodes = [n for n in nodes.values() if n["type"] == "source"]
    deg = defaultdict(int)
    for (a, b), e in edges.items():
        if e["kind"] == "entity":
            deg[b] += 1
    for (a, b), e in edges.items():
        if e["kind"] != "entity":
            continue
        n = nodes[b]
        src = nodes[a]
        if (e.get("share", 0) >= args.infra_share and src.get("raw_events", 0) >= 50) or \
                (len(src_nodes) >= 5 and deg[b] >= 0.6 * len(src_nodes)):
            n["infra"] = True
    # cap entities per source node for drawing (table keeps all)
    keep = set(nodes)
    by_src = defaultdict(list)
    for (a, b), e in edges.items():
        if e["kind"] == "entity":
            by_src[a].append((e["count"], b))
    dropped = 0
    for a, lst in by_src.items():
        lst.sort(reverse=True)
        for _, b in lst[args.max_entities:]:
            if not nodes[b].get("seed") and not nodes[b].get("hidden"):
                nodes[b]["hidden"] = True
                dropped += 1

    # full entity list -> CSV (the HTML only carries what a browser can handle)
    out = args.output or str(Path(args.case[0]) / (("combined_" if len(args.case) > 1 else "") +
                                                ("graph_sanitized.html" if args.sanitize else "graph.html")))
    srcs_of = defaultdict(list)
    for (a, b), e in edges.items():
        if e["kind"] == "entity":
            srcs_of[b].append(nodes[a]["label"])
    all_ents = sorted((n for n in nodes.values() if n["type"] != "source" and not n.get("seed")),
                      key=lambda n: -n["count"])
    csv_path = None
    if not args.sanitize:
        csv_path = str(Path(out).with_name(Path(out).stem + "_entities.csv"))
        with open(csv_path, "w", encoding="utf-8-sig", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["type", "value", "events", "first_utc", "last_utc", "infrastructure", "in_graph", "sources"])
            for n in all_ents:
                w.writerow([n["type"], n["label"], n["count"],
                            datetime.fromtimestamp(n["first"], timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if n["first"] else "",
                            datetime.fromtimestamp(n["last"], timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if n["last"] else "",
                            "yes" if n.get("infra") else "", "" if n.get("hidden") else "yes",
                            " | ".join(sorted(srcs_of[n["id"]]))])
            for k, (cnt, tmin, tmax, mask) in sorted(tail.items(), key=lambda kv: -kv[1][0]):
                full = nodes.get(k)    # rare here, but a full node elsewhere: already written above
                if full is not None:
                    continue
                typ, _, val = k.partition(":")
                w.writerow([typ, val, cnt,
                            datetime.fromtimestamp(tmin, timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                            datetime.fromtimestamp(tmax, timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), "", "",
                            " | ".join(sorted(l for i, l in enumerate(tail_src) if mask >> i & 1))])
    # keep in the HTML: everything drawn, plus the busiest hidden entities for the table
    nodes_all = set(nodes)
    extra = [n["id"] for n in all_ents if n.get("hidden")][:args.table_limit]
    keep_ids = {n["id"] for n in nodes.values() if n["type"] == "source" or n.get("seed") or not n.get("hidden")}
    keep_ids.update(extra)
    left_out = len(nodes) - len(keep_ids)
    if left_out:
        nodes = {k: v for k, v in nodes.items() if k in keep_ids}
        edges = {k: v for k, v in edges.items() if k[0] in keep_ids and k[1] in keep_ids}
        samples = defaultdict(list, {k: v for k, v in samples.items() if k[0] in keep_ids and k[1] in keep_ids})

    # read back the sample events that are still referenced
    wanted = defaultdict(set)
    for v in samples.values():
        for x in v:
            if isinstance(x, tuple):
                wanted[x[0]].add(x[1])
    texts = {}
    if not args.sanitize:
        for fpath, lines in wanted.items():
            with open(fpath, encoding="utf-8") as fh:
                for i, line in enumerate(fh):
                    if i in lines:
                        r = json.loads(line).get("_raw")
                        r = r if isinstance(r, str) else json.dumps(r)
                        texts[(fpath, i)] = (r if args.no_redact else redact(r))[:600]
    for k in list(samples):
        samples[k] = [x if isinstance(x, dict) else {"t": x[2], "raw": texts.get((x[0], x[1]), "")}
                      for x in samples[k]]

    # sanitisation
    mapping = {}
    if args.sanitize:
        counters = defaultdict(int)
        for n in sorted(nodes.values(), key=lambda n: (n["first"] or 0)):
            typ = n["type"]
            if typ == "source":
                counters["idx"] += 1
                n["label"] = f"SOURCE_{counters['idx']}"
                n.pop("by_index", None)
                n.pop("by_st", None)
            else:
                counters[typ] += 1
                ph = f"{typ.upper()}_{counters[typ]}"
                mapping[n["label"]] = ph
                n["label"] = ph
        samples.clear()

    # serialise
    def ser_node(n):
        o = {k: v for k, v in n.items() if k != "seeds"}
        o["seeds"] = sorted(mapping.get(s, s) for s in n["seeds"]) if args.sanitize else sorted(n["seeds"])
        return o
    out_nodes = [ser_node(n) for n in nodes.values()]
    out_edges = []
    for e in edges.values():
        bins = sorted(e["bins"].items())
        out_edges.append({"s": e["s"], "t": e["t"], "kind": e["kind"], "count": e["count"],
                          "b": [[k, v] for k, v in bins], "share": round(e.get("share", 0), 4),
                          "ft": e.get("first"), "last": e.get("last")})
    samp = {} if args.sanitize else {f"{a}|{b}": v for (a, b), v in samples.items()}
    seeds_out = [{"value": mapping.get(s["value"], s["value"]) if args.sanitize else s["value"],
                  "key": seed_keys[s["value"].lower()], "earliest": s["earliest"], "latest": s["latest"],
                  "variants": s.get("variants", ["as given"])}
                 for s in case["seeds"]]
    case_label, splunk_cfg = " + ".join(str(Path(c)) for c in args.case), {"base": (args.splunk_base or SETTINGS["splunk_base"]).rstrip("/"),
                                                                                    "locale": args.locale or SETTINGS["splunk_locale"],
                                                                                    "app": args.app or SETTINGS["splunk_app"] or "search"}
    if args.sanitize:
        # node ids embed raw values (ip:..., st:index/sourcetype): replace every id with an opaque one
        idmap = {n["id"]: f"n{i}" for i, n in enumerate(out_nodes)}
        for n in out_nodes:
            n["id"] = idmap[n["id"]]
        for e in out_edges:
            e["s"], e["t"] = idmap[e["s"]], idmap[e["t"]]
        for sd in seeds_out:
            sd["key"] = idmap.get(sd["key"], sd["key"])
            sd["earliest"] = sd["latest"] = ""
        case_label, splunk_cfg = "<case>", {"base": "", "locale": "", "app": ""}
    data = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "title": args.title, "sanitized": bool(args.sanitize), "bin": bin_s,
        "api": None if args.sanitize else args.voyager_api,
        "nodes": out_nodes, "edges": out_edges, "samples": samp, "seeds": seeds_out,
        "case": case_label, "cases": [] if args.sanitize else [str(Path(c)) for c in args.case],
        "splunk": splunk_cfg,
    }
    blob = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    Path(out).write_text(TEMPLATE.replace("__TITLE__", html.escape(args.title)).replace("__DATA__", blob),
                         encoding="utf-8")
    ents = all_ents
    n_tail = sum(1 for k in tail if k not in nodes_all)
    for e in edges.values():
        if e["kind"] == "cooccur":
            print(f"seed link {nodes[e['s']]['label']!r} <-> {nodes[e['t']]['label']!r}: {e['count']} event(s)",
                  file=sys.stderr)
    print(f"Graph: {len(case['seeds'])} seed(s), {len(src_nodes)} source node(s), {len(ents) + n_tail:,} entities "
          f"({sum(1 for n in ents if n.get('infra'))} infrastructure, {dropped} hidden beyond --max-entities). "
          f"Written to {out} ({os.path.getsize(out) / 1e6:.1f} MB)", file=sys.stderr)
    left_out += n_tail
    if left_out:
        print(f"{left_out:,} low-count hidden entities left out of the HTML table (--table-limit {args.table_limit:,})"
              + (f"; all are in {csv_path}" if csv_path else ""), file=sys.stderr)
    elif csv_path:
        print(f"Entity list: {csv_path}", file=sys.stderr)


def ent_key_for_seed(v):
    s = v.strip()
    if RE_IP.fullmatch(s):
        return f"ip:{s}"
    if re.match(r"(?i)^https?://", s):
        return f"url:{s.lower()}"
    if RE_EMAIL.fullmatch(s):
        return f"email:{s.lower()}"
    if re.fullmatch(r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}", s) and s.rsplit(".", 1)[-1].lower() in TLDS:
        return f"domain:{s.lower()}"
    return f"ioc:{s.lower()}"


# =========================================================================== status
def cmd_status(args):
    case = case_load(args.case)
    if not case["seeds"]:
        print("No seeds yet.")
        return
    for sd in case["seeds"]:
        seed_dir = Path(args.case) / "seeds" / sd["slug"]
        nodes = stage1_nodes(seed_dir / "stage1") if (seed_dir / "stage1").is_dir() else {}
        pulled = {(json.loads(Path(p).read_text())["index"], json.loads(Path(p).read_text())["sourcetype"])
                  for p in glob.glob(str(seed_dir / "raw" / "*" / "node.json"))}
        found = ""
        bins = [b for d in nodes.values() for b in d["bins"]]
        if bins:
            f = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:00")
            found = f"   found {f(min(bins))} -> {f(max(bins))} UTC"
        print(f"\n{sd['value']}  [searched {sd['earliest']} -> {sd['latest']}]{found}")
        for (idx, st), d in sorted(nodes.items(), key=lambda kv: -kv[1]["count"]):
            print(f"  {'raw' if (idx, st) in pulled else '   '} {d['count']:>12,}  {idx} / {st}")


# =========================================================================== template
TEMPLATE = open(HERE / "pivot_graph_template.html", encoding="utf-8").read() \
    if (HERE / "pivot_graph_template.html").is_file() else "__EMBEDDED__"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("seed", help="stage-1 counts + raw pulls for an IOC (resumable)")
    s.add_argument("case", help="case folder (created if missing)")
    s.add_argument("ioc", help="IOC to search for (IP, domain, URL, email, account, password, file name...)")
    s.add_argument("--reset-range", action="store_true",
                   help="the value is already in the case with another time range: drop its results and search again")
    s.add_argument("--no-variants", action="store_true",
                   help="search only the IOC as given (default also searches URL-decoded/encoded forms)")
    s.add_argument("--earliest", required=True)
    s.add_argument("--latest", required=True)
    s.add_argument("--max-events", type=int, default=500000, help="pull raw only for nodes up to this size")
    s.add_argument("--include", action="append", default=[], help="force raw pull for index/sourcetype containing this")
    s.add_argument("--stage1-only", action="store_true")
    s.add_argument("--base-search", help='replace "index=*" (e.g. "index=a OR index=b")')
    s.add_argument("--chunk-stage1", default="1d")
    s.add_argument("--chunk-raw", default="6h", help="max window size inside an active range")
    s.add_argument("--gap-hours", type=int, default=2,
                   help="raw pulls cover only hours with stage-1 hits; gaps up to this many hours are bridged")
    s.add_argument("--max-jobs", type=int, default=2)
    s.add_argument("--app", default=None, help="app context (default: Voyager settings, else your default app)")
    s.add_argument("--exporter", default=str(EXPORTER))
    s.add_argument("--base")
    s.add_argument("--locale", default=None, help="locale in Splunk URLs (default: Voyager settings)")
    s.add_argument("--db")
    s.add_argument("--cookies")
    s.add_argument("--poll")
    s.add_argument("--dry-run", action="store_true")

    b = sub.add_parser("build", help="extract entities locally and write the HTML graph")
    b.add_argument("case", nargs="+", help="one or more case folders; several are combined into one graph")
    b.add_argument("-o", "--output")
    b.add_argument("--bin", type=int, default=5,
                   help="time resolution in minutes: 1, 5 (default), 15 or 60. Pulled sources use their exact "
                        "event times; sources over the pull limit only have hourly counts")
    b.add_argument("--group", choices=["sourcetype", "index", "index-sourcetype"], default="sourcetype",
                   help="one source node per sourcetype (default; its indexes are merged), per index, "
                        "or per index/sourcetype pair (the old behaviour)")
    b.add_argument("--table-limit", type=int, default=20000,
                   help="hidden (not drawn) entities kept in the HTML table, busiest first (default 20000); "
                        "the full list always goes to *_entities.csv")
    b.add_argument("--title", default="IOC pivot graph")
    b.add_argument("--voyager-api", help=argparse.SUPPRESS)   # set by the Voyager GUI: in-page "Search it" buttons
    b.add_argument("--sanitize", action="store_true", help="replace every identifier by a placeholder, drop raw samples")
    b.add_argument("--no-redact", action="store_true",
                   help="keep credentials in URLs / password= fields as found (default: redacted in the graph)")
    b.add_argument("--max-entities", type=int, default=80, help="entities drawn per source node (all are in the table)")
    b.add_argument("--infra-share", type=float, default=0.5,
                   help="entity in at least this share of a node's events is flagged as infrastructure")
    b.add_argument("--splunk-base", default=None, help="for pivot links (default: Voyager settings)")
    b.add_argument("--locale", default=None)
    b.add_argument("--app", default=None)

    t = sub.add_parser("status", help="show what the case holds")
    t.add_argument("case")

    a = ap.parse_args()
    {"seed": cmd_seed, "build": cmd_build, "status": cmd_status}[a.cmd](a)


if __name__ == "__main__":
    main()

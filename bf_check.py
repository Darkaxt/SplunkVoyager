"""Quick brute-force check of an entity-mapper dump: who sent failed logons to whom.

  python bf_check.py data\\investigations\\<case>                       all directions with failures and, for
                                                                       each value the entity mapper searched (the
                                                                       seeds), what it sent and what it received
  python bf_check.py data\\investigations\\<case> idt014958 10.1.2.3    the same for these systems instead

Uses the parsers of auth_analysis.py (Oracle audit, listener and alert logs, Windows Security, Linux auth).
Source = the client (address, and host name when the log has it); destination = the system that logged the
failure (database and its host, Windows computer, Linux host). A system is matched by any part of its name or
address, case-insensitively, and a host name also by its short form and the reverse ("idt014958.example.org"
matches a log that says "idt014958").
"""
import argparse
import json
import re
import sys
from pathlib import Path
from collections import Counter, defaultdict

import auth_analysis as aa

FAIL = ("invalid credentials", "locked", "expired", "other failure")


def src_label(e):
    if e["src_host"] and e["src_ip"]:
        return f"{e['src_host']} ({e['src_ip']})"
    return e["src_host"] or e["src_ip"] or "(unknown)"


def dst_label(e):
    t = e["target"] if e["kind"] == "logon" else (e["target"] or "")
    return f"{e['target_host']}" + (f" / {t}" if t and t != e["target_host"] else "")


def flows(events):
    """(source, destination) -> counts, accounts, first/last failure; logons plus listener / outbound failures."""
    f = defaultdict(lambda: {"n": Counter(), "accounts": Counter(), "first": None, "last": None, "kinds": Counter(),
                             "codes": Counter()})
    for e in events:
        if e["kind"] == "alert logon":
            continue
        x = f[(src_label(e), dst_label(e))]
        x["n"][e["result"]] += 1
        x["kinds"][e["kind"]] += 1
        if e["result"] != "success":
            if e["account"]:
                x["accounts"][e["account"]] += 1
            x["codes"][f"{e['code']} {e['meaning']}".strip()] += 1
            if e["t"] is not None:
                x["first"] = e["t"] if x["first"] is None else min(x["first"], e["t"])
                x["last"] = e["t"] if x["last"] is None else max(x["last"], e["t"])
    return f


def matcher(name):
    """Any part of the name or address; a host name also matches its short form and the reverse
    (idt014958.example.org matches a log that says idt014958)."""
    q = name.lower().strip()
    short = q.split(".")[0] if not re.fullmatch(r"[\d.:]+", q) else None

    def match(label):
        lab = label.lower()
        toks = [t for t in re.split(r"[^\w.:\-]+", lab) if t]
        if short is None:                              # an address: the whole address only (10.1.1.1 is not 10.1.1.10)
            return q in toks
        if q in lab:
            return True
        return any(t.split(".")[0] == short for t in toks)
    return match


def fails(x):
    return sum(x["n"][r] for r in FAIL)


def table(rows, top):
    out = []
    w_s = min(max([len(s) for (s, _), _ in rows[:top]] + [6]), 48)
    w_d = min(max([len(d) for (_, d), _ in rows[:top]] + [11]), 56)
    out.append(f"{'SOURCE':<{w_s}}  {'DESTINATION':<{w_d}}  {'BAD PWD':>7} {'LOCKED':>6} {'OTHER':>6} {'OK':>6}  "
               f"{'FIRST FAILURE (UTC)':<19}  {'LAST FAILURE (UTC)':<19}  ACCOUNTS (failures)")
    for (s, d), x in rows[:top]:
        acc = ", ".join(f"{a} {n}" for a, n in x["accounts"].most_common(4)) + (f", +{len(x['accounts']) - 4} more" if len(x["accounts"]) > 4 else "")
        out.append(f"{s[:w_s]:<{w_s}}  {d[:w_d]:<{w_d}}  {x['n']['invalid credentials']:>7,} {x['n']['locked']:>6,} "
                   f"{x['n']['expired'] + x['n']['other failure']:>6,} {x['n']['success']:>6,}  "
                   f"{aa.utc(x['first']):<19}  {aa.utc(x['last']):<19}  {acc}")
    if len(rows) > top:
        out.append(f"... {len(rows) - top} more (use --top)")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("case", help="investigation folder (or its entities folder)")
    ap.add_argument("systems", nargs="*", help="systems to place: name or address, or any part of it "
                                               "(default: the values the entity mapper searched)")
    ap.add_argument("--top", type=int, default=25, help="rows per table (default 25)")
    ap.add_argument("--min", type=int, default=1, help="hide directions with fewer failures (default 1)")
    a = ap.parse_args()
    systems = a.systems
    if not systems:
        root = Path(a.case)
        ed = root / "entities" if (root / "entities").is_dir() else root
        try:
            systems = [s["value"] for s in json.loads((ed / "case.json").read_text(encoding="utf-8")).get("seeds", [])]
        except (OSError, ValueError):
            systems = []
        if systems:
            print("Systems: the values the entity mapper searched: " + ", ".join(systems), file=sys.stderr)
    events, _ = aa.read_dump(a.case, log=lambda m: print(m, file=sys.stderr, flush=True))
    f = flows(events)
    rows = sorted(((k, x) for k, x in f.items() if fails(x) >= a.min), key=lambda kv: -fails(kv[1]))
    total = sum(fails(x) for _, x in rows)
    cred = sum(x["n"]["invalid credentials"] + x["n"]["locked"] for _, x in rows)
    print(f"\nFailed logons and connections by direction: {total:,} failures in {len(rows)} source -> destination pairs, "
          f"{cred:,} of them wrong password or locked account\n"
          "BAD PWD = invalid credentials (ORA-01017, Windows bad password, sshd Failed); LOCKED = account locked "
          "(ORA-28000, 4740); OTHER = any other failure (privileges, listener / network errors, expired)\n")
    print(table(rows, a.top) if rows else "No failures found.")

    for sysname in systems:
        m = matcher(sysname)
        sent = [(k, x) for k, x in rows if m(k[0])]
        recv = [(k, x) for k, x in rows if m(k[1])]
        ok_sent = sum(x["n"]["success"] for k, x in f.items() if m(k[0]))
        ok_recv = sum(x["n"]["success"] for k, x in f.items() if m(k[1]))
        s_n, r_n = sum(fails(x) for _, x in sent), sum(fails(x) for _, x in recv)
        sc = lambda xs: sum(x["n"]["invalid credentials"] + x["n"]["locked"] for _, x in xs)
        own = [k for k, _ in sent if m(k[1])]
        print(f"\n{'=' * 100}\n{sysname}")
        print(f"  as SOURCE      : {s_n:,} failures ({sc(sent):,} wrong password / locked) sent to {len({k[1] for k, _ in sent})} "
              f"destination(s), {len({a for _, x in sent for a in x['accounts']})} account(s); {ok_sent:,} successful logons/connections sent")
        print(f"  as DESTINATION : {r_n:,} failures ({sc(recv):,} wrong password / locked) received from {len({k[0] for k, _ in recv})} "
              f"source(s), {len({a for _, x in recv for a in x['accounts']})} account(s); {ok_recv:,} successful logons/connections received")
        if own:
            print(f"  ({len(own)} of these pairs go from {sysname} to itself, so they appear in both lines)")
        if not sent and not recv:
            print("  not found in any failed logon or connection (check the name: any part of it matches)")
        if sent:
            print(f"\n  Failures sent by {sysname}:\n" + "\n".join("  " + l for l in table(sent, a.top).splitlines()))
        if recv:
            print(f"\n  Failures received by {sysname}:\n" + "\n".join("  " + l for l in table(recv, a.top).splitlines()))
        codes = Counter()
        for _, x in {k: x for k, x in sent + recv}.items():      # a pair from the system to itself once
            codes.update(x["codes"])
        if codes:
            print("\n  Codes: " + " · ".join(f"{c} ×{n:,}" for c, n in codes.most_common(6)))


if __name__ == "__main__":
    main()

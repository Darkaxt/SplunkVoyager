"""Quick brute-force check of an entity-mapper dump: who sent failed logons to whom.

  python bf_check.py data\\investigations\\<case>                       all directions with failures
  python bf_check.py data\\investigations\\<case> idt014958 10.1.2.3    ... and, for each system named,
                                                                       what it sent and what it received

Uses the parsers of auth_analysis.py (Oracle audit, listener and alert logs, Windows Security, Linux auth).
Source = the client (address, and host name when the log has it); destination = the system that logged the
failure (database and its host, Windows computer, Linux host). A system is matched by any part of its name or
address, case-insensitively ("idt014958" matches "idt014958.example.org").
"""
import argparse
import sys
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


def fails(x):
    return sum(x["n"][r] for r in FAIL)


def table(rows, top):
    out = []
    w_s = min(max([len(s) for (s, _), _ in rows[:top]] + [6]), 48)
    w_d = min(max([len(d) for (_, d), _ in rows[:top]] + [11]), 56)
    out.append(f"{'SOURCE':<{w_s}}  {'DESTINATION':<{w_d}}  {'FAILED':>7} {'LOCKED':>6} {'OK':>6}  {'FIRST FAILURE (UTC)':<19}  "
               f"{'LAST FAILURE (UTC)':<19}  ACCOUNTS (failures)")
    for (s, d), x in rows[:top]:
        acc = ", ".join(f"{a} {n}" for a, n in x["accounts"].most_common(4)) + (f", +{len(x['accounts']) - 4} more" if len(x["accounts"]) > 4 else "")
        out.append(f"{s[:w_s]:<{w_s}}  {d[:w_d]:<{w_d}}  {fails(x):>7,} {x['n']['locked']:>6,} {x['n']['success']:>6,}  "
                   f"{aa.utc(x['first']):<19}  {aa.utc(x['last']):<19}  {acc}")
    if len(rows) > top:
        out.append(f"... {len(rows) - top} more (use --top)")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("case", help="investigation folder (or its entities folder)")
    ap.add_argument("systems", nargs="*", help="systems to place: name or address, or any part of it")
    ap.add_argument("--top", type=int, default=25, help="rows per table (default 25)")
    ap.add_argument("--min", type=int, default=1, help="hide directions with fewer failures (default 1)")
    a = ap.parse_args()
    events, _ = aa.read_dump(a.case, log=lambda m: print(m, file=sys.stderr, flush=True))
    f = flows(events)
    rows = sorted(((k, x) for k, x in f.items() if fails(x) >= a.min), key=lambda kv: -fails(kv[1]))
    total = sum(fails(x) for _, x in rows)
    print(f"\nFailed logons and connections by direction: {total:,} failures in {len(rows)} source -> destination pairs\n")
    print(table(rows, a.top) if rows else "No failures found.")

    for sysname in a.systems:
        q = sysname.lower()
        sent = [(k, x) for k, x in rows if q in k[0].lower()]
        recv = [(k, x) for k, x in rows if q in k[1].lower()]
        ok_sent = sum(x["n"]["success"] for k, x in f.items() if q in k[0].lower())
        ok_recv = sum(x["n"]["success"] for k, x in f.items() if q in k[1].lower())
        s_n, r_n = sum(fails(x) for _, x in sent), sum(fails(x) for _, x in recv)
        print(f"\n{'=' * 100}\n{sysname}")
        print(f"  as SOURCE      : {s_n:,} failures sent to {len({k[1] for k, _ in sent})} destination(s), "
              f"{len({a for _, x in sent for a in x['accounts']})} account(s); {ok_sent:,} successful logons/connections sent")
        print(f"  as DESTINATION : {r_n:,} failures received from {len({k[0] for k, _ in recv})} source(s), "
              f"{len({a for _, x in recv for a in x['accounts']})} account(s); {ok_recv:,} successful logons/connections received")
        if not sent and not recv:
            print("  not found in any failed logon or connection (check the name: any part of it matches)")
        if sent:
            print(f"\n  Failures sent by {sysname}:\n" + "\n".join("  " + l for l in table(sent, a.top).splitlines()))
        if recv:
            print(f"\n  Failures received by {sysname}:\n" + "\n".join("  " + l for l in table(recv, a.top).splitlines()))
        codes = Counter()
        for _, x in sent + recv:
            codes.update(x["codes"])
        if codes:
            print("\n  Codes: " + " · ".join(f"{c} ×{n:,}" for c, n in codes.most_common(6)))


if __name__ == "__main__":
    main()

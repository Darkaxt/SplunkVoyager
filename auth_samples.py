"""Pick sample authentication events from an entity-mapper dump, a few per sourcetype and per kind (failed,
successful, lockout, other), so the log formats can be seen without browsing every folder.

  python auth_samples.py data\\investigations\\<case>                 -> <case>\\auth_samples.txt
  python auth_samples.py data\\investigations\\<case> --mask-ips -n 4 --all

Reads the dump as it is (loose part files or zips). Only sourcetypes that look authentication-related are
looked at unless --all. Events of the same shape (digits ignored) are shown once. Review the file before
sharing it: --mask-ips replaces IPv4 addresses consistently, user names and host names are left as they are.
"""
import argparse
import ipaddress
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import exportfiles

RELEVANT = re.compile(r"oracle|linux|secure|auth|win|syslog|sshd|weblogic|db", re.I)
KINDS = [
    ("lockout", re.compile(r"ORA-0*28000|\b28000\b|account (is )?locked|locked out|\b4740\b|LOCKED", re.I)),
    ("failed", re.compile(r"ORA-0*1017|invalid username|logon denied|failed password|authentication failure|"
                          r"\b4625\b|\b1017\b|login failed|auth(entication)? fail|FAILED|incorrect password", re.I)),
    ("successful", re.compile(r"\b4624\b|accepted (password|publickey|keyboard)|session opened|\bestablish\b|"
                              r"LOGON|CONNECT|logged in|login succe", re.I)),
]
IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")


def shape(raw):
    return re.sub(r"\d+", "#", raw)[:300]


def kind_of(raw):
    for k, rx in KINDS:
        if rx.search(raw):
            return k
    return "other"


def masker():
    seen = {}

    def sub(m):
        ip = m.group(1)
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return ip
        if ip not in seen:
            n = len(seen) + 1
            seen[ip] = f"10.255.{n // 250}.{n % 250 + 1}"
        return seen[ip]
    return lambda s: IPV4.sub(sub, s)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("case", help="investigation folder (or its entities folder)")
    ap.add_argument("-n", type=int, default=3, help="samples per sourcetype and kind (default 3)")
    ap.add_argument("--all", action="store_true", help="every sourcetype, not only authentication-looking ones")
    ap.add_argument("--mask-ips", action="store_true", help="replace IPv4 addresses (consistently)")
    ap.add_argument("--max-events", type=int, default=200000, help="events read per folder at most")
    ap.add_argument("-o", "--output")
    a = ap.parse_args()
    root = Path(a.case)
    seeds = root / "entities" / "seeds" if (root / "entities").is_dir() else root / "seeds" if (root / "seeds").is_dir() else root
    dirs = sorted(p for p in seeds.glob("*/raw/*") if p.is_dir())
    if not dirs:
        sys.exit(f"No raw folders under {seeds}")
    mask = masker() if a.mask_ips else (lambda s: s)
    picked = defaultdict(lambda: defaultdict(list))      # sourcetype -> kind -> [(host, time, raw)]
    shapes = defaultdict(set)
    counts = defaultdict(lambda: defaultdict(int))
    for d in dirs:
        meta = {}
        try:
            meta = json.loads((d / "node.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        name = d.name
        if not a.all and not RELEVANT.search(name):
            continue
        read = 0
        for part in exportfiles.parts(d, "jsonl"):
            with part.open() as fh:
                for line in fh:
                    if read >= a.max_events:
                        break
                    try:
                        r = json.loads(line)
                    except ValueError:
                        continue
                    r = r.get("result", r) if isinstance(r, dict) else {}
                    raw = str(r.get("_raw") or "")
                    if not raw:
                        continue
                    read += 1
                    st = r.get("sourcetype") or meta.get("sourcetype") or name
                    k = kind_of(raw)
                    counts[st][k] += 1
                    sh = shape(raw)
                    if len(picked[st][k]) < a.n and (k, sh) not in shapes[st]:
                        shapes[st].add((k, sh))
                        picked[st][k].append((r.get("host", ""), r.get("_time", ""), raw[:3000]))
    out = Path(a.output) if a.output else (root / "auth_samples.txt")
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"Sample events from {seeds} (kinds guessed by keywords; review before sharing)\n")
        for st in sorted(picked):
            fh.write(f"\n{'=' * 100}\nSOURCETYPE {st}   events read: "
                     + ", ".join(f"{k} {n:,}" for k, n in sorted(counts[st].items())) + "\n")
            for k in ("failed", "lockout", "successful", "other"):
                for host, t, raw in picked[st].get(k, []):
                    fh.write(f"\n--- {k} | host {mask(str(host))} | {t}\n{mask(raw)}\n")
    print(f"{sum(len(v) for s in picked.values() for v in s.values())} samples from {len(picked)} sourcetype(s) -> {out}")


if __name__ == "__main__":
    main()

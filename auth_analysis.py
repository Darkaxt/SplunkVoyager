"""Authentication analysis of an entity-mapper dump: failed, locked and successful logons per account and per
source, from the raw events the entity mapper exported. Facts only, as an HTML report and a CSV of every
parsed event.

  python auth_analysis.py data\\investigations\\<case>        -> <case>\\entities\\auth_report.html (+ auth_events.csv)

Formats parsed (from _raw; the dump holds _time, _raw, index, sourcetype, host):
  oracle:audit:db       LOGON rows: USERNAME, RETURNCODE, DB_NAME / CDB_NAME / CLUSTER_NAME, USERHOST, client
                        address, OS user, DBLINK_INFO
  oracle:audit:text     CONNECT records (length-prefixed fields): DATABASE USER, STATUS, PRIVILEGE, CLIENT USER,
                        USERHOST, CLIENT ADDRESS
  oracle:listener:xml   connections: source address, client host / user / program, service, result code
                        (context: a listener doesn't see authentication)
  oracle:alert:xml      "logon successful" blocks (context) and outbound "Fatal NI connect error" failures
  Windows Security      4624, 4625, 4648, 4740, 4771, 4776 (key=value or XML rendering)
  Linux auth / syslog   sshd Accepted / Failed / Invalid user, pam authentication failure, faillock
The same event found under several mapped values is counted once.
"""
import argparse
import csv
import glob
import hashlib
import html
import json
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import exportfiles

ORA = {0: "success", 1017: "invalid username/password", 28000: "account locked", 28001: "password expired",
       28002: "success, password will expire", 1045: "user lacks CREATE SESSION privilege", 1005: "null password given",
       1031: "insufficient privileges", 28009: "SYS connection must be as SYSDBA or SYSOPER",
       28040: "no matching authentication protocol", 1040: "invalid character in password", 1004: "default username not supported",
       1035: "only users with RESTRICTED SESSION may log on", 1033: "initialization or shutdown in progress"}
TNS = {0: "connection established", 12514: "listener does not know the requested service", 12505: "listener does not know the SID",
       12541: "no listener", 12545: "target host or object does not exist", 12564: "connection refused",
       12170: "connect timeout", 12519: "no appropriate service handler", 12516: "no handler with a matching protocol stack",
       12518: "listener could not hand off the connection", 12537: "connection closed", 12547: "lost contact",
       12560: "protocol adapter error", 3136: "inbound connection timed out", 12528: "all handlers blocking new connections"}
WIN = {"0xc000006a": "bad password", "0xc0000064": "user name does not exist", "0xc000006d": "bad user name or authentication information",
       "0xc0000234": "account locked out", "0xc0000072": "account disabled", "0xc0000193": "account expired",
       "0xc0000071": "password expired", "0xc0000224": "password must change", "0xc000006f": "outside logon hours",
       "0xc0000070": "workstation restriction", "0xc000015b": "logon type not granted", "0x0": "success"}
RESULTS = ("success", "invalid credentials", "locked", "expired", "other failure")


def ora_result(code):
    if code in (0, 28002):
        return "success"
    if code == 1017:
        return "invalid credentials"
    if code == 28000:
        return "locked"
    if code == 28001:
        return "expired"
    return "other failure"


def _epoch(s):
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def utc(t, fmt="%Y-%m-%d %H:%M:%S"):
    return datetime.fromtimestamp(t, timezone.utc).strftime(fmt) if t is not None else ""


ADDR_HOST = re.compile(r"\(HOST=([^)]*)\)", re.I)
ADDR_PORT = re.compile(r"\(PORT=(\d+)\)", re.I)


def _client(addr):
    h, p = ADDR_HOST.search(addr or ""), ADDR_PORT.search(addr or "")
    return (h.group(1) if h else ""), (p.group(1) if p else "")


# ------------------------------------------------------------------ parsers: each returns a list of events (dicts)
KV = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')


def p_audit_db(raw, ev):
    if 'ACTION_NAME="LOGON"' not in raw:
        return []
    f = dict(KV.findall(raw))
    try:
        code = int(f.get("RETURNCODE", ""))
    except ValueError:
        return []
    comment = f.get("COMMENT_TEXT", "")
    ip, port = _client(comment.split("Client address:", 1)[1] if "Client address:" in comment else "")
    dbl = re.search(r"SOURCE_DB_NAME=([^,)]+).*?DBLINK_NAME=([^,)]+)", comment)
    auth = re.search(r"Authenticated by: ([^;]+)", comment)
    return [dict(ev, kind="logon", account=f.get("USERNAME", ""), code=str(code), result=ora_result(code),
                 meaning=ORA.get(code, f"ORA-{code:05d}"),
                 target=f.get("DB_NAME", "") + (f" ({f['CDB_NAME']})" if f.get("CDB_NAME") else ""),
                 target_host=f.get("CLUSTER_NAME") or ev["host"], src_ip=ip, src_port=port, src_host=f.get("USERHOST", ""),
                 os_user=f.get("OS_USERNAME", ""), program="", privilege="", auth=auth.group(1).strip() if auth else "",
                 via=(f"db link {dbl.group(2)} from {dbl.group(1)}" if dbl else ""))]


TXT_FIELD = re.compile(r"(?m)^([A-Z][A-Z _]*?)\s*:\[(\d+)\] '")


def text_fields(raw):
    """Oracle OS audit record: NAME:[length] 'value' - the length is used to skip multi-line values exactly."""
    out, pos = {}, 0
    while True:
        m = TXT_FIELD.search(raw, pos)
        if not m:
            return out
        n = int(m.group(2))
        out.setdefault(m.group(1).strip(), raw[m.end():m.end() + n])
        pos = m.end() + n


def p_audit_text(raw, ev):
    if "'CONNECT'" not in raw and "ACTION NUMBER:[3] '100'" not in raw:
        return []
    f = text_fields(raw)
    if f.get("ACTION", "").strip().upper() != "CONNECT" and f.get("ACTION NUMBER") != "100":
        return []
    try:
        code = int(f.get("STATUS", ""))
    except ValueError:
        return []
    ip, port = _client(f.get("CLIENT ADDRESS", ""))
    user = f.get("DATABASE USER", "")
    return [dict(ev, kind="logon", account=("/ (OS authenticated)" if user == "/" else user), code=str(code),
                 result=ora_result(code), meaning=ORA.get(code, f"ORA-{code:05d}"),
                 target=f"DBID {f['DBID']}" if f.get("DBID") else "", target_host=ev["host"], src_ip=ip, src_port=port,
                 src_host=f.get("USERHOST", ""), os_user=f.get("CLIENT USER", ""), program="",
                 privilege=f.get("PRIVILEGE", "") if f.get("PRIVILEGE", "NONE") != "NONE" else "", auth="", via="")]


LSN = re.compile(r"\* \(CONNECT_DATA=(.*?)\) \* \(ADDRESS=\(PROTOCOL=\w+\)\(HOST=([^)]*)\)\(PORT=(\d+)\)\) \* (\w+) \* (\S+) \* (\d+)", re.S)


def _cd(s, k):
    m = re.search(r"\(" + k + r"=([^)]*)\)", s, re.I)
    return m.group(1) if m else ""


def p_listener(raw, ev):
    out = []
    lh = re.search(r"host_id='([^']*)'", raw)
    for m in LSN.finditer(raw):
        cd, code = m.group(1), int(m.group(6))
        out.append(dict(ev, kind="connection", account=_cd(cd, "USER"), code=str(code),
                        result="success" if code == 0 else "other failure", meaning=TNS.get(code, f"TNS-{code:05d}"),
                        target=_cd(cd, "SERVICE_NAME") or _cd(cd, "SID") or m.group(5),
                        target_host=lh.group(1) if lh else ev["host"], src_ip=m.group(2), src_port=m.group(3),
                        src_host=_cd(cd, "HOST"), os_user=_cd(cd, "USER"), program=_cd(cd, "PROGRAM"), privilege="",
                        auth="", via=m.group(4)))
    return out


ALERT_LOGON = re.compile(r"(\S+?)\(\d+\):Session \([\d,]+\): (\S+) logon (successful|failed|denied): DB Logon User: ([^,]+), "
                         r"Remote Machine: ([^,]+), Program: (.*?), OS User: (\S+)")
ALERT_IP = re.compile(r"Session \(([\d,]+)\): \S+ logon \w+: Client IP Address: (\S+)")
NI = re.compile(r"Fatal NI connect error (\d+), connecting to:\s*(\(.*?)(?:\n\s*\n|\n\s+VERSION|\Z)", re.S)


def p_alert(raw, ev):
    out = []
    ips = {m.group(1): m.group(2) for m in ALERT_IP.finditer(raw)}
    for m in ALERT_LOGON.finditer(raw):
        sess = re.search(r"Session \(([\d,]+)\)", raw[m.start():m.end()])
        ok = m.group(3) == "successful"
        out.append(dict(ev, kind="alert logon", account=m.group(4).strip(), code="", result="success" if ok else "other failure",
                        meaning=f"{m.group(2)} logon {m.group(3)}", target=m.group(1), target_host=ev["host"],
                        src_ip=ips.get(sess.group(1) if sess else "", ""), src_port="", src_host=m.group(5).strip(),
                        os_user=m.group(7), program=m.group(6).strip(), privilege="", auth="", via=""))
    for m in NI.finditer(raw):
        desc, code = m.group(2), int(m.group(1))
        cid = re.search(r"CID=\(PROGRAM=[^)]*\)\(HOST=([^)]*)\)", desc, re.I)
        cid_host = cid.group(1) if cid else ""
        dest = [h for h in re.findall(r"\(HOST=([^)]*)\)", desc, re.I) if h.lower() != cid_host.lower()]
        out.append(dict(ev, kind="outbound failure", account=_cd(desc, "USER"), code=str(code), result="other failure",
                        meaning=TNS.get(code, f"TNS-{code:05d}"), target=_cd(desc, "SERVICE_NAME") or _cd(desc, "SID"),
                        target_host=", ".join(dict.fromkeys(dest))[:200], src_ip="", src_port="", src_host=ev["host"],
                        os_user=_cd(desc, "USER"), program=_cd(desc, "PROGRAM"), privilege="", auth="", via=""))
    return out


WIN_KV = re.compile(r"(?:Data Name=['\"](\w+)['\"]>([^<]*)<|<(EventID|Computer)>([^<]*)<|\b(\w+)=(?:'([^']*)'|\"([^\"]*)\"|(\S+)))")


def p_windows(raw, ev):
    if not re.search(r"(EventID[=>]['\"]?)(4624|4625|4648|4740|4771|4776)\b", raw):
        return []
    f = {}
    for m in WIN_KV.finditer(raw):
        k = m.group(1) or m.group(3) or m.group(5)
        v = m.group(2) if m.group(1) else m.group(4) if m.group(3) else next((x for x in m.group(6, 7, 8) if x is not None), "")
        f.setdefault(k, v)
    eid = f.get("EventID", "")
    status = (f.get("SubStatus") if f.get("SubStatus", "0x0").lower() not in ("0x0", "") else f.get("Status", "")) or ""
    status = status.lower()
    if eid == "4624":
        res, meaning = "success", f"logon type {f.get('LogonType', '?')}"
    elif eid == "4740":
        res, meaning = "locked", "account locked out"
    elif eid == "4648":
        res, meaning = "success", "logon with explicit credentials"
    elif eid in ("4776", "4771") and status in ("0x0", ""):
        res, meaning = "success", "credential validation"
    else:
        res = {"0xc0000234": "locked", "0xc0000071": "expired", "0xc0000193": "expired"}.get(status, "invalid credentials"
              if status in ("0xc000006a", "0xc0000064", "0xc000006d", "0x18", "0x17") or eid == "4625" else "other failure")
        meaning = WIN.get(status, status or "failure")
    ip = f.get("IpAddress", "")
    return [dict(ev, kind="logon", account=f.get("TargetUserName", ""), code=f"{eid} {status}".strip(), result=res,
                 meaning=meaning, target=f.get("TargetDomainName", ""), target_host=f.get("Computer") or ev["host"],
                 src_ip="" if ip in ("-", "::1", "127.0.0.1") else ip, src_port=f.get("IpPort", ""),
                 src_host=f.get("WorkstationName", "") if f.get("WorkstationName", "-") != "-" else "",
                 os_user=f.get("SubjectUserName", ""), program=f.get("ProcessName", ""), privilege="",
                 auth=f.get("AuthenticationPackageName", "") or f.get("LogonProcessName", ""), via="")]


SSH = [(re.compile(r"Accepted (\S+) for (\S+) from (\S+) port (\d+)"), "success"),
       (re.compile(r"Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port (\d+)"), "invalid credentials"),
       (re.compile(r"(Invalid) user (\S+) from (\S+)(?: port (\d+))?"), "invalid credentials")]


def p_linux(raw, ev):
    if "sshd" not in raw and "pam_" not in raw and "faillock" not in raw:
        return []
    out = []
    for rx, res in SSH:
        m = rx.search(raw)
        if m:
            out.append(dict(ev, kind="logon", account=m.group(2), code="sshd", result=res, meaning=f"sshd {m.group(1).lower()}",
                            target="ssh", target_host=ev["host"], src_ip=m.group(3), src_port=m.group(4) or "", src_host="",
                            os_user="", program="sshd", privilege="", auth=m.group(1), via=""))
            return out
    m = re.search(r"authentication failure;.*?rhost=(\S*)\s+user=(\S+)", raw)
    if m:
        return [dict(ev, kind="logon", account=m.group(2), code="pam", result="invalid credentials", meaning="pam authentication failure",
                     target=(re.search(r"\b(\w[\w-]*)(?:\[\d+\])?: pam_", raw) or [None, ""])[1], target_host=ev["host"],
                     src_ip=m.group(1), src_port="", src_host="", os_user="", program="", privilege="", auth="pam", via="")]
    m = re.search(r"(?:Consecutive login failures for user|faillock.*?user) (\S+) account temporarily locked", raw)
    if m:
        return [dict(ev, kind="logon", account=m.group(1), code="faillock", result="locked", meaning="account temporarily locked",
                     target="", target_host=ev["host"], src_ip="", src_port="", src_host="", os_user="", program="", privilege="",
                     auth="pam_faillock", via="")]
    return []


def parser_for(st):
    s = (st or "").lower()
    if "oracle:audit:db" in s:
        return p_audit_db
    if "oracle:audit:text" in s:
        return p_audit_text
    if "oracle:listener" in s:
        return p_listener
    if "oracle:alert" in s:
        return p_alert
    if "wineventlog" in s or "xmlwineventlog" in s:
        return p_windows
    if "linux" in s or "secure" in s or "syslog" in s or "auth" in s:
        return p_linux
    return None


# ------------------------------------------------------------------ reading the dump
def read_dump(case, log=print):
    """All parsed events from every raw folder under the case (seeds/*/raw/*), each event once."""
    root = Path(case)
    ed = root / "entities" if (root / "entities").is_dir() else root
    dirs = sorted(p for p in (ed / "seeds").glob("*/raw/*") if p.is_dir())
    if not dirs:
        raise SystemExit(f"No raw folders under {ed / 'seeds'}")
    events, seen, stats = [], set(), Counter()
    t0, last = time.time(), time.time()
    for i, d in enumerate(dirs, 1):
        meta = {}
        try:
            meta = json.loads((d / "node.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        for part in exportfiles.parts(d, "jsonl"):
            with part.open() as fh:
                for line in fh:
                    try:
                        r = json.loads(line)
                    except ValueError:
                        continue
                    r = r.get("result", r) if isinstance(r, dict) else {}
                    raw = str(r.get("_raw") or "")
                    st = r.get("sourcetype") or meta.get("sourcetype") or ""
                    p = parser_for(st)
                    stats["read"] += 1
                    if not p or not raw:
                        continue
                    key = hashlib.blake2b(f"{st}\x00{r.get('host', '')}\x00{r.get('_time', '')}\x00{raw}".encode(
                        "utf-8", "surrogatepass"), digest_size=12).digest()
                    if key in seen:
                        stats["duplicates"] += 1
                        continue
                    seen.add(key)
                    t = _epoch(r.get("_time"))
                    base = {"t": t, "sourcetype": st, "host": r.get("host", ""), "raw": raw[:2500]}
                    try:
                        evs = p(raw, base)
                    except Exception as e:            # one odd event never stops the analysis
                        stats[f"unparsed {st}"] += 1
                        continue
                    for e in evs:
                        events.append(e)
                        stats[f"{st}: {e['kind']}"] += 1
        if time.time() - last > 20 or i == len(dirs):
            last = time.time()
            log(f"Read {i}/{len(dirs)} folders, {stats['read']:,} events, {len(events):,} authentication / connection events")
    events.sort(key=lambda e: (e["t"] is None, e["t"] or 0))     # events without a readable time last
    return events, stats


# ------------------------------------------------------------------ facts
def _src(e):
    return e["src_ip"] or e["src_host"] or "(unknown)"


def analyse(events):
    logons = [e for e in events if e["kind"] == "logon"]
    acc = defaultdict(lambda: {"n": Counter(), "first": {}, "last": {}, "src": Counter(), "programs": Counter(),
                               "os_users": Counter(), "via": Counter(), "codes": Counter(), "seq": []})
    for e in logons:
        k = (e["account"], e["target"], e["target_host"])
        a = acc[k]
        a["n"][e["result"]] += 1
        a["first"].setdefault(e["result"], e["t"])
        a["last"][e["result"]] = e["t"]
        a["src"][_src(e) + (f" ({e['src_host']})" if e["src_ip"] and e["src_host"] else "")] += 1
        if e["os_user"]:
            a["os_users"][e["os_user"]] += 1
        if e["via"]:
            a["via"][e["via"]] += 1
        a["codes"][f"{e['code']} {e['meaning']}"] += 1
        a["seq"].append(e)
    accounts = []
    for (account, target, th), a in acc.items():
        fails = [x for x in a["seq"] if x["result"] != "success"]
        succ_after = next((x for x in a["seq"] if x["result"] == "success" and fails and x["t"] >= fails[0]["t"]), None)
        locked_t = a["first"].get("locked")
        accounts.append({"account": account, "target": target, "target_host": th,
                         **{r: a["n"][r] for r in RESULTS}, "attempts": sum(a["n"].values()),
                         "first_failure": fails[0]["t"] if fails else None, "last_failure": fails[-1]["t"] if fails else None,
                         "first_locked": locked_t, "first_success": a["first"].get("success"),
                         "last_success": a["last"].get("success"),
                         "success_after_failure": succ_after["t"] if succ_after else None,
                         "success_after_lock": next((x["t"] for x in a["seq"] if x["result"] == "success" and locked_t
                                                     and x["t"] > locked_t), None),
                         "sources": a["src"].most_common(), "os_users": a["os_users"].most_common(5),
                         "via": a["via"].most_common(5), "codes": a["codes"].most_common(),
                         "events": [_slim(x) for x in a["seq"] if x["result"] != "success"][:30]
                                   + [_slim(x) for x in a["seq"] if x["result"] == "success"][:5]})
    accounts.sort(key=lambda a: (-(a["invalid credentials"] + a["locked"] + a["expired"] + a["other failure"]), a["account"]))

    srcs = defaultdict(lambda: {"n": Counter(), "accounts": set(), "failed_accounts": Counter(), "targets": set(),
                                "first": None, "last": None, "fail_times": [], "hosts": set()})
    for e in logons:
        s = srcs[_src(e)]
        s["n"][e["result"]] += 1
        s["accounts"].add(e["account"])
        s["targets"].add(e["target"] or e["target_host"])
        if e["src_host"] and e["src_ip"]:
            s["hosts"].add(e["src_host"])
        if e["result"] != "success":
            s["failed_accounts"][e["account"]] += 1
            s["fail_times"].append(e["t"] or 0)
        s["first"] = e["t"] if s["first"] is None else s["first"]
        s["last"] = e["t"]
    sources = []
    for k, s in srcs.items():
        ft, peak, j = sorted(s["fail_times"]), 0, 0
        for i in range(len(ft)):                       # most failures within any 10 minutes
            while ft[i] - ft[j] > 600:
                j += 1
            peak = max(peak, i - j + 1)
        fails = sum(v for r, v in s["n"].items() if r != "success")
        sources.append({"source": k, "hosts": sorted(s["hosts"]), **{r: s["n"][r] for r in RESULTS}, "failures": fails,
                        "accounts": len(s["accounts"]), "failed_accounts": len(s["failed_accounts"]),
                        "targets": len(s["targets"]), "target_list": sorted(t for t in s["targets"] if t)[:50],
                        "first": s["first"], "last": s["last"], "peak_10min": peak,
                        "max_per_account": max(s["failed_accounts"].values(), default=0)})
    sources.sort(key=lambda s: (-s["failures"], s["source"]))

    hourly = defaultdict(Counter)
    for e in logons:
        if e["t"]:
            hourly[int(e["t"] // 3600) * 3600][e["result"]] += 1

    conn = defaultdict(lambda: {"n": Counter(), "first": None, "last": None})
    for e in events:
        if e["kind"] == "connection":
            c = conn[(e["src_ip"], e["src_host"], e["os_user"], e["program"], e["target"], e["target_host"])]
            c["n"][f"{e['code']} {e['meaning']}"] += 1
            c["first"] = c["first"] or e["t"]
            c["last"] = e["t"]
    connections = sorted(({"src_ip": k[0], "src_host": k[1], "user": k[2], "program": k[3], "service": k[4], "listener": k[5],
                           "count": sum(v["n"].values()), "results": v["n"].most_common(), "first": v["first"], "last": v["last"]}
                          for k, v in conn.items()), key=lambda c: -c["count"])
    out = defaultdict(lambda: {"n": 0, "first": None, "last": None})
    for e in events:
        if e["kind"] == "outbound failure":
            o = out[(e["src_host"], e["target_host"], e["target"], f"{e['code']} {e['meaning']}")]
            o["n"] += 1
            o["first"] = o["first"] or e["t"]
            o["last"] = e["t"]
    outbound = sorted(({"from": k[0], "to": k[1], "service": k[2], "error": k[3], "count": v["n"], "first": v["first"],
                        "last": v["last"]} for k, v in out.items()), key=lambda o: -o["count"])
    alerts = [_slim(e) for e in events if e["kind"] == "alert logon"][:2000]
    return {"accounts": accounts, "sources": sources, "hourly": sorted((h, dict(c)) for h, c in hourly.items()),
            "connections": connections[:2000], "outbound": outbound[:2000], "alert_logons": alerts,
            "totals": dict(Counter(e["result"] for e in logons)), "logons": len(logons),
            "first": min((e["t"] for e in logons if e["t"] is not None), default=None),
            "last": max((e["t"] for e in logons if e["t"] is not None), default=None),
            "untimed": sum(1 for e in logons if e["t"] is None),
            "by_sourcetype": dict(Counter(e["sourcetype"] for e in logons))}


def _slim(e):
    return {k: e[k] for k in ("t", "sourcetype", "host", "account", "code", "result", "meaning", "target", "target_host",
                              "src_ip", "src_port", "src_host", "os_user", "program", "privilege", "via", "raw")}


def write_csv(events, path):
    cols = ["time_utc", "kind", "result", "code", "meaning", "account", "target", "target_host", "src_ip", "src_port",
            "src_host", "os_user", "program", "privilege", "auth", "via", "sourcetype", "host"]
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for e in events:
            w.writerow([utc(e["t"])] + [e.get(c, "") for c in cols[1:]])


def render(facts, stats, title):
    tpl = (Path(__file__).with_name("auth_report_template.html")).read_text(encoding="utf-8")
    data = {"title": title, "generated": utc(time.time()), "facts": facts,
            "stats": {k: v for k, v in stats.items()}, "ora": {str(k): v for k, v in ORA.items()}}
    blob = json.dumps(data, ensure_ascii=False, default=str).replace("</", "<\\/")
    return tpl.replace("__TITLE__", html.escape(title)).replace("__DATA__", blob)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("case", help="investigation folder (or its entities folder)")
    ap.add_argument("-o", "--output", help="HTML report (default: <entities>/auth_report.html)")
    ap.add_argument("--title", default="Authentication analysis")
    a = ap.parse_args()
    root = Path(a.case)
    ed = root / "entities" if (root / "entities").is_dir() else root
    log = lambda m: print(m, file=sys.stderr, flush=True)
    events, stats = read_dump(root, log)
    facts = analyse(events)
    out = Path(a.output) if a.output else ed / "auth_report.html"
    write_csv(events, out.with_name("auth_events.csv"))
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_text(render(facts, stats, a.title), encoding="utf-8")
    tmp.replace(out)
    t = facts["totals"]
    log(f"{facts['logons']:,} logon attempts ({', '.join(f'{k} {v:,}' for k, v in sorted(t.items()))}), "
        f"{len(facts['accounts'])} account/target pairs, {len(facts['sources'])} sources, "
        f"{len(facts['connections'])} listener connection groups, {len(facts['outbound'])} outbound failure groups -> {out}")


if __name__ == "__main__":
    main()

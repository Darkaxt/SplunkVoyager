"""Voyager tests: python -m unittest discover -s tests   (Payload Analyzer has its own in payload_analyzer/tests)."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import network_feed  # noqa: E402


class NetworkFeedTest(unittest.TestCase):
    def test_query_maps_fields_and_keeps_extraction(self):
        spl = network_feed.build_query("index=web", '| rex field=uri "(?<uri_path>[^?]*)"', {"site": "host", "src": "clientip"})
        lines = spl.splitlines()
        self.assertEqual(lines[0], "index=web")
        self.assertTrue(lines[1].startswith("| rex"))
        self.assertIn("| eval site='host', src='clientip'", spl)
        self.assertTrue(lines[-1].endswith("by site uri_path uri_query"))

    def test_query_rejects_injection_in_field_names(self):
        with self.assertRaises(ValueError):
            network_feed.build_query("index=web", "", {"site": "host' | delete"})
        with self.assertRaises(ValueError):
            network_feed.build_query("   ", "", {})
        q = network_feed.build_query("index=web")
        self.assertIn("req_bytes=coalesce(tonumber('cs_bytes'), tonumber('cs_B'), tonumber('bytes_out'))", q)
        self.assertIn("sum(resp_bytes) as resp_bytes count(resp_bytes) as resp_n max(resp_bytes) as resp_max", q)
        q = network_feed.build_query("index=web", "", {"req_bytes": "-", "resp_bytes": "bytes"})
        self.assertNotIn("req_bytes", q)
        self.assertIn("resp_bytes=tonumber('bytes')", q)
        with self.assertRaises(ValueError):
            network_feed.build_query("index=web", "", {"resp_bytes": "sc_bytes, x' | delete"})

    def test_merge_combines_windows_and_writes_utc(self):
        with tempfile.TemporaryDirectory() as d:
            rows1 = [{"site": "a.example", "uri_path": "/x", "uri_query": "q=1", "count": "2", "et": "1792540800.000",
                      "lt": "1792540900.000", "src": "192.0.2.1", "status": "200", "action": "allowed"}]
            rows2 = [{"site": "a.example", "uri_path": "/x", "uri_query": "q=1", "count": "3", "et": "1792627200.000",
                      "lt": "1792627300.000", "src": ["192.0.2.1", "192.0.2.2"], "status": ["200", "500"], "action": "allowed"},
                     {"site": "a.example", "uri_path": "/y", "uri_query": "", "count": "1", "et": "1792627200",
                      "lt": "1792627200", "src": "192.0.2.3", "status": "404", "action": "blocked"}]
            for i, rows in enumerate((rows1, rows2), 1):
                Path(d, f"part-{i:04d}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
            out = Path(d, "requests.jsonl")
            network_feed.merge(d, out)
            got = [json.loads(l) for l in out.read_text().splitlines()]
        self.assertEqual(len(got), 2)
        x = got[0]
        self.assertEqual((x["uri_path"], x["count"]), ("/x", 5))
        self.assertEqual(x["src"], ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(x["status"], ["200", "500"])
        self.assertEqual(x["et"], "2026-10-21 00:00:00")
        self.assertEqual(x["lt"], "2026-10-22 00:01:40")

    def test_large_merge_in_buckets_matches(self):
        """Exports too big for memory are merged through on-disk buckets in several processes: same rows."""
        import random, zipfile
        rnd = random.Random(3)
        with tempfile.TemporaryDirectory() as d:
            for w in range(1, 7):
                rows = [{"result": {"site": f"s{rnd.randint(1, 3)}.example", "uri_path": f"/p{rnd.randint(1, 9)}",
                                    "uri_query": f"id={rnd.randint(1, 400)}", "count": str(rnd.randint(1, 5)),
                                    "et": str(1792540800 + w * 3600), "lt": str(1792540800 + w * 3600 + 60),
                                    "src": f"192.0.2.{rnd.randint(1, 50)}", "status": "200", "action": "allowed",
                                    "resp_bytes": "4000", "resp_n": "1", "resp_max": "4000"}} for _ in range(500)]
                text = "".join(json.dumps(r) + "\n" for r in rows)
                if w % 2:                                    # some windows already compressed, as in a real run
                    with zipfile.ZipFile(Path(d, f"part-{w:04d}.jsonl.zip"), "w", zipfile.ZIP_DEFLATED) as z:
                        z.writestr(f"part-{w:04d}.jsonl", text)
                else:
                    Path(d, f"part-{w:04d}.jsonl").write_text(text)
            msgs = []
            network_feed.merge(d, Path(d, "one.jsonl"), log=msgs.append)
            network_feed.merge(d, Path(d, "many.jsonl"), log=msgs.append, bucket_rows=250, workers=2)
            one = sorted(Path(d, "one.jsonl").read_text().splitlines())
            many = sorted(Path(d, "many.jsonl").read_text().splitlines())
            self.assertEqual(one, many)
            self.assertGreater(len(one), 1000)
            self.assertTrue(any("Pass 1 of 2" in m for m in msgs) and any("Merge pass 2: " in m for m in msgs), msgs)
            self.assertFalse(list(Path(d).glob("*.buckets")))  # temporary buckets removed


class WebAppTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        import voyager_settings
        cls.vs = voyager_settings
        cls._orig = voyager_settings.SETTINGS_PATH
        voyager_settings.SETTINGS_PATH = Path(cls.tmp.name) / "settings.json"
        for k in ("SPLUNK_BASE", "SPLUNK_LOCALE", "SPLUNK_APP", "VOYAGER_URL"):
            os.environ.pop(k, None)
        from app import create_app
        cls.app = create_app()
        cls.c = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        cls.vs.SETTINGS_PATH = cls._orig
        cls.tmp.cleanup()

    def test_settings_and_userscript(self):
        r = self.c.post("/api/settings", json={"splunk_base": "https://splunk.example.com/", "splunk_locale": "en-GB"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["splunk_base"], "https://splunk.example.com")
        self.assertEqual(self.vs.splunk_url("config"), "https://splunk.example.com/en-GB/config")
        js = self.c.get("/voyager.user.js").get_data(as_text=True)
        self.assertIn("// @match        https://splunk.example.com/*", js)
        self.assertIn("http://localhost/api/receive_cookies", js)
        self.assertEqual(self.c.post("/api/settings", json={"splunk_base": "not a url"}).status_code, 400)

    def test_blocklist(self):
        import blocklist
        bl = blocklist.Blocklist(blocklist.DEFAULT + "203.0.113.0/24\n*.cdn.example\n=http://exact\nre:\\.local(/|$)\n")
        hidden = {"a": "single-label name", "http://a": "single-label name", "www.w3.org": "w3.org",
                  "http://www.w3.org/1999/XSL/Transform": "w3.org", "xml.apache.org": "apache.org",
                  "http://203.0.113.9:8080/x": "203.0.113.0/24", "x.cdn.example": "*.cdn.example",
                  "http://exact": "=http://exact", "intranet.local": "re:\\.local(/|$)"}
        for v, rule in hidden.items():
            self.assertEqual(bl.match(v), rule, v)
        for v in ("cb.attacker.example", "evilw3.org", "localhost", "127.0.0.1", "198.51.100.23", "http://exact.example"):
            self.assertIsNone(bl.match(v), v)
        self.assertIsNone(blocklist.Blocklist("", single_label=False).match("http://a"))
        self.assertEqual(blocklist.suggest("http://cdn.evil.co.uk/x.js"), "evil.co.uk")
        self.assertEqual(blocklist.suggest("http://1.2.3.4/x"), "1.2.3.4")
        # through the app: the default list, a bad regex refused, an entry added from a findings row
        self.assertIn("w3.org", self.c.get("/api/settings").get_json()["blocklist"])
        self.assertEqual(self.c.post("/api/settings", json={"blocklist": "re:(unclosed"}).status_code, 400)
        r = self.c.post("/api/blocklist/add", json={"entry": "evil.example"})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["blocklist"].rstrip().endswith("evil.example"))
        self.assertEqual(self.c.post("/api/blocklist/suggest", json={"value": "http://a.b.evil.example/"}).get_json(),
                         {"entry": "evil.example"})
        f = blocklist.filter_findings({"sources": [{"value": "198.51.100.23"}],
                                       "callbacks": [{"value": "http://x.evil.example/p"}, {"value": "cb.attacker.example"}]},
                                      blocklist.from_settings())
        self.assertEqual([c["value"] for c in f["callbacks"]], ["cb.attacker.example"])
        self.assertEqual(f["hidden"]["callbacks"][0]["rule"], "evil.example")

    def test_several_instances(self):
        self.vs.SETTINGS_PATH.write_text(json.dumps({"splunk_base": "https://old.example.com", "splunk_locale": "en-GB"}))
        s = self.vs.load()                                   # single-URL settings convert to one instance
        self.assertEqual([(i["name"], i["locale"]) for i in s["instances"]], [("old.example.com", "en-GB")])
        r = self.c.post("/api/settings", json={"instances": [
            {"name": "prod", "base": "https://splunk.example.com/", "locale": "en-GB", "app": "secops"},
            {"name": "lab", "base": "https://lab-splunk.example.org", "locale": ""}], "default_instance": "lab"})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        s = self.vs.load()
        self.assertEqual(s["splunk_base"], "https://lab-splunk.example.org")      # default instance
        self.assertEqual(self.vs.instance(".example.com")["name"], "prod")         # by cookie domain
        self.assertEqual(self.vs.instance("splunk.example.com")["app"], "secops")
        self.assertEqual(self.vs.instance("nowhere.test")["name"], "lab")           # unknown -> default
        with self.vs.use_instance("splunk.example.com"):
            self.assertEqual(self.vs.splunk_url("config"), "https://splunk.example.com/en-GB/config")
        self.assertEqual(self.vs.splunk_url("config"), "https://lab-splunk.example.org/en-US/config")
        js = self.c.get("/voyager.user.js").get_data(as_text=True)
        self.assertIn("// @match        https://splunk.example.com/*", js)
        self.assertIn("// @match        https://lab-splunk.example.org/*", js)
        for o in ("https://splunk.example.com", "https://lab-splunk.example.org"):
            pre = self.c.options("/api/receive_cookies", headers={"Origin": o, "Access-Control-Request-Method": "POST"})
            self.assertEqual(pre.headers.get("Access-Control-Allow-Origin"), o)
        bad = self.c.post("/api/settings", json={"instances": [{"name": "a", "base": "https://x.example"},
                                                               {"name": "A", "base": "https://y.example"}]})
        self.assertEqual(bad.status_code, 400)

    def test_origin_guard(self):
        self.c.post("/api/settings", json={"splunk_base": "https://splunk.example.com"})
        evil = {"Origin": "https://evil.example"}
        self.assertEqual(self.c.post("/api/inv", json={"name": "x", "earliest": "-1d"}, headers=evil).status_code, 403)
        self.assertEqual(self.c.post("/api/request_refresh", json={}, headers=evil).status_code, 403)
        self.assertEqual(self.c.post("/api/receive_cookies", json={}, headers=evil).status_code, 403)
        self.assertEqual(self.c.post("/api/inv", data="name=x").status_code, 415)   # plain form posts refused
        pre = self.c.options("/api/receive_cookies", headers={"Origin": "https://splunk.example.com",
                                                              "Access-Control-Request-Method": "POST"})
        self.assertEqual(pre.headers.get("Access-Control-Allow-Origin"), "https://splunk.example.com")
        self.assertIsNone(self.c.options("/api/receive_cookies", headers=evil).headers.get("Access-Control-Allow-Origin"))

    def test_files_stay_inside_investigation(self):
        from app.services import workbench as wb
        self.c.post("/api/settings", json={"instances": [{"base": "https://splunk.example.com"}]})
        with tempfile.TemporaryDirectory() as d:
            orig = wb.INV_ROOT
            wb.INV_ROOT = Path(d)
            try:
                inv = wb.create_investigation("Guard test", "-1d", "now")
                (Path(d) / inv["slug"] / "x.html").write_text("ok")
                self.assertEqual(self.c.get(f"/inv/{inv['slug']}/files/x.html").status_code, 200)
                self.assertEqual(self.c.get(f"/inv/{inv['slug']}/files/../../settings.json").status_code, 404)
                self.assertEqual(self.c.get(f"/inv/{inv['slug']}/files/investigation.py").status_code, 404)
                self.assertEqual(self.c.get("/inv/..%2f..%2fapp/files/x.html").status_code, 404)
                evil = {"Origin": "https://evil.example"}
                self.assertEqual(self.c.delete(f"/api/inv/{inv['slug']}", headers=evil).status_code, 403)
                # double check: refused with what would be removed until the name is typed
                r = self.c.delete(f"/api/inv/{inv['slug']}", json={})
                self.assertEqual(r.status_code, 409)
                c = r.get_json()["confirm"]
                self.assertEqual(c["type"], "Guard test")
                self.assertNotIn("token", c)
                self.assertTrue(any("cannot be undone" in l for l in c["lines"]))
                self.assertEqual(self.c.delete(f"/api/inv/{inv['slug']}", json={"confirm": "guard test"}).status_code, 409)
                self.assertTrue((Path(d) / inv["slug"]).exists())
                self.assertEqual(self.c.delete(f"/api/inv/{inv['slug']}", json={"confirm": "Guard test"}).status_code, 200)
                self.assertFalse((Path(d) / inv["slug"]).exists())
                self.assertEqual(self.c.get(f"/investigations/{inv['slug']}").status_code, 404)
            finally:
                wb.INV_ROOT = orig


class ExportFilesTest(unittest.TestCase):
    def write_parts(self, d, n=3):
        for i in range(1, n + 1):
            (d / f"part-{i:04d}.jsonl").write_text(f'{{"n": {i}, "_raw": "{"x" * 500}"}}\n' * 50)

    def test_pack_read_and_replace(self):
        import exportfiles
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            self.write_parts(d)
            key = str(d / "part-0003.jsonl")                    # e.g. a sample pointer kept by an entity graph
            self.assertEqual(exportfiles.pack(d, log=lambda m: None), 3)
            self.assertEqual(sorted(p.name for p in d.iterdir()),
                             ["part-0001.jsonl.zip", "part-0002.jsonl.zip", "part-0003.jsonl.zip"])
            self.assertLess((d / "part-0001.jsonl.zip").stat().st_size, 50 * 520 / 5)     # compressed
            got = [p.name for p in exportfiles.parts(d, "jsonl")]
            self.assertEqual(got, ["part-0001.jsonl", "part-0002.jsonl", "part-0003.jsonl"])
            with exportfiles.open_part(key) as fh:             # pointers to the loose file still work
                self.assertEqual(json.loads(fh.readline())["n"], 3)
            # a window downloaded again (--retry-failed) wins over the compressed copy, then replaces it
            (d / "part-0002.jsonl").write_text('{"n": 22}\n')
            with [p for p in exportfiles.parts(d, "jsonl") if p.name == "part-0002.jsonl"][0].open() as fh:
                self.assertEqual(fh.read(), '{"n": 22}\n')
            exportfiles.pack(d, log=lambda m: None)
            with exportfiles.open_part(str(d / "part-0002.jsonl.zip") + "::part-0002.jsonl") as fh:
                self.assertEqual(fh.read(), '{"n": 22}\n')
            self.assertEqual(len(exportfiles.parts(d, "jsonl")), 3)
            # runs packed by older versions (one export.zip) are still read; per-window zips win over it
            import zipfile
            with zipfile.ZipFile(d / "export.zip", "w") as z:
                z.writestr("part-0001.jsonl", '{"n": "old"}\n')
                z.writestr("part-0004.jsonl", '{"n": 4}\n')
            ps = {p.name: p for p in exportfiles.parts(d, "jsonl")}
            self.assertEqual(sorted(ps), ["part-0001.jsonl", "part-0002.jsonl", "part-0003.jsonl", "part-0004.jsonl"])
            with ps["part-0001.jsonl"].open() as fh:
                self.assertEqual(json.loads(fh.readline())["n"], 1)

    def test_only_finished_windows_and_one_packer_at_a_time(self):
        import exportfiles
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            self.write_parts(d)
            (d / "manifest.json").write_text(json.dumps({"windows": [
                {"state": "done", "file": "part-0001.jsonl"}, {"state": "downloading", "file": "part-0002.jsonl"},
                {"state": "done", "file": "part-0003.jsonl"}]}))
            (d / "part-0003.jsonl.zip.tmp").write_text("")      # another process is compressing it
            self.assertEqual(exportfiles.sweep(d, log=lambda m: None), 1)
            self.assertEqual(sorted(p.name for p in d.glob("part-*")),
                             ["part-0001.jsonl.zip", "part-0002.jsonl", "part-0003.jsonl", "part-0003.jsonl.zip.tmp"])
            old = time.time() - 3600                            # a crash left it: taken over
            os.utime(d / "part-0003.jsonl.zip.tmp", (old, old))
            self.assertEqual(exportfiles.pack_done(d, log=lambda m: None), 1)
            self.assertTrue((d / "part-0003.jsonl.zip").is_file())
            self.assertFalse((d / "part-0003.jsonl.zip.tmp").exists())

    def test_pack_command(self):
        with tempfile.TemporaryDirectory() as d:
            for name, state in (("done", "done"), ("busy", "running")):
                r = Path(d, "case", name)
                r.mkdir(parents=True)
                (r / "part-0001.csv").write_text("a,b\n1,2\n")
                (r / "manifest.json").write_text(json.dumps({"windows": [{"state": state, "file": "part-0001.csv"}]}))
            out = subprocess.run([sys.executable, str(ROOT / "exportfiles.py"), "pack", str(Path(d, "case"))],
                                 capture_output=True, text=True).stdout
            self.assertIn("1 part file(s) compressed in 2 run(s)", out)
            self.assertTrue(Path(d, "case", "done", "part-0001.csv.zip").is_file())
            self.assertTrue(Path(d, "case", "busy", "part-0001.csv").is_file())


class AuthAnalysisTest(unittest.TestCase):
    def test_dump_to_facts_and_report(self):
        import auth_analysis
        import auth_fixture
        with tempfile.TemporaryDirectory() as d:
            auth_fixture.build(d)
            events, stats = auth_analysis.read_dump(d, log=lambda m: None)
            self.assertEqual(stats["duplicates"], 25)                       # same events under two mapped values
            f = auth_analysis.analyse(events)
            self.assertEqual(f["logons"], 18)
            self.assertEqual(f["totals"], {"invalid credentials": 11, "locked": 3, "success": 4})
            acc = {(a["account"], a["target"]): a for a in f["accounts"]}
            bs = acc[("BS_APP", "PAYDB_01_P (CDB01)")]
            self.assertEqual((bs["invalid credentials"], bs["locked"], bs["success"]), (3, 2, 1))
            self.assertEqual(auth_analysis.utc(bs["first_locked"]), "2026-11-26 08:03:00")
            self.assertEqual(auth_analysis.utc(bs["success_after_lock"]), "2026-11-26 08:30:00")
            self.assertEqual(bs["sources"][0], ("10.9.8.7 (apphost1.example)", 6))
            self.assertIn("db link PAY.EXAMPLE from HRDB_01_A", dict(acc[("SVC_LINK", "PAYDB_01_P (CDB01)")]["via"]))
            # OS audit: only CONNECT records; SQL text holding STATUS:[4] '1017' or LOCKED_BY is not a logon
            text = [e for e in events if e["sourcetype"] == "oracle:audit:text"]
            self.assertEqual(sorted((e["account"], e["code"], e["privilege"]) for e in text), [("SCOTT", "1017", ""), ("SYS", "0", "SYSDBA")])
            src = {s["source"]: s for s in f["sources"]}["10.9.8.7"]
            self.assertEqual((src["failed_accounts"], src["max_per_account"], src["peak_10min"]), (9, 5, 5))
            self.assertEqual({(c["service"], c["results"][0][0]) for c in f["connections"]},
                             {("PAYDB_TAF.example", "0 connection established"), ("NOPE.example", "12514 listener does not know the requested service")})
            self.assertEqual(f["outbound"][0]["to"], "10.3.3.3, 10.3.3.4")
            self.assertEqual((f["alert_logons"][0]["account"], f["alert_logons"][0]["src_ip"]), ("RECO", "10.1.1.1"))
            win = {e["code"]: e for e in events if e["sourcetype"] == "XmlWinEventLog"}
            self.assertEqual((win["4625 0xc000006a"]["result"], win["4625 0xc000006a"]["meaning"]), ("invalid credentials", "bad password"))
            self.assertEqual(win["4740"]["result"], "locked")
            # report and CSV
            subprocess.run([sys.executable, str(ROOT / "auth_analysis.py"), d], check=True, capture_output=True)
            html_ = Path(d, "entities", "auth_report.html").read_text(encoding="utf-8")
            self.assertIn('"logons": 18', html_)
            self.assertNotIn("__DATA__", html_)
            rows = Path(d, "entities", "auth_events.csv").read_text(encoding="utf-8-sig").splitlines()
            self.assertEqual(len(rows), 1 + 22)


class UpdaterTest(unittest.TestCase):
    """updater.py against a throwaway remote: update, local-edit guard, rollback and skip."""

    def git(self, cwd, *a):
        return subprocess.run(["git", "-C", str(cwd), "-c", "user.name=t", "-c", "user.email=t@t", *a],
                              capture_output=True, text=True, check=True).stdout.strip()

    def test_update_cycle(self):
        import importlib.util
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            src = t / "src"
            src.mkdir()
            (src / "updater.py").write_text((ROOT / "updater.py").read_text())
            (src / "requirements.txt").write_text("")
            self.git(src, "init", "-q", "-b", "main")
            self.git(src, "add", "-A")
            self.git(src, "commit", "-qm", "one")
            subprocess.run(["git", "clone", "-q", "--bare", str(src), str(t / "remote.git")], check=True)
            subprocess.run(["git", "clone", "-q", str(t / "remote.git"), str(t / "inst")], check=True)
            subprocess.run(["git", "clone", "-q", str(t / "remote.git"), str(t / "dev")], check=True)
            spec = importlib.util.spec_from_file_location("updater_t", t / "inst" / "updater.py")
            up = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(up)
            self.assertEqual(up.check(), 0)
            (t / "dev" / "f.txt").write_text("two")
            self.git(t / "dev", "add", "-A"); self.git(t / "dev", "commit", "-qm", "two"); self.git(t / "dev", "push", "-q")
            self.assertEqual(up.check(), 1)
            self.assertIsNone(up.status["blocked"])
            (t / "inst" / "updater.py").write_text((t / "inst" / "updater.py").read_text() + "\n# local edit\n")
            up.check()
            self.assertIn("edited locally", up.status["blocked"])
            self.assertFalse(up.apply(log=lambda m: None))
            self.git(t / "inst", "checkout", "-q", "updater.py")
            self.assertTrue(up.apply(log=lambda m: None))
            self.assertEqual((t / "inst" / "f.txt").read_text(), "two")
            self.assertTrue(up.rollback(log=lambda m: None))        # as if the new version had not started
            self.assertFalse((t / "inst" / "f.txt").exists())
            up.check()
            self.assertIn("rolled back", up.status["blocked"])     # that version is not retried


class EndToEndTest(unittest.TestCase):
    """Both modules against the mock Splunk: export -> merge -> Payload Analyzer -> findings, and pivot seed/build."""

    @classmethod
    def setUpClass(cls):
        import mock_splunk
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), mock_splunk.H)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        cls.tmp = tempfile.TemporaryDirectory()
        cls.env = dict(os.environ, SPLUNK_COOKIE="splunkd_8000=test", SPLUNK_BASE=cls.base, SPLUNK_LOCALE="en-US",
                       VOYAGER_URL="http://127.0.0.1:9", PYTHONIOENCODING="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.tmp.cleanup()

    def run_py(self, *argv, isolated=False):
        cmd = [sys.executable] + (["-I"] if isolated else []) + [str(a) for a in argv]
        r = subprocess.run(cmd, cwd=ROOT, env=self.env, capture_output=True, text=True, timeout=600)
        self.assertEqual(r.returncode, 0, r.stdout[-2000:] + r.stderr[-4000:])
        return r

    def test_network_pipeline(self):
        d = Path(self.tmp.name, "net")
        spl = network_feed.build_query("index=web sourcetype=access_combined")
        self.run_py("splunk_export.py", "run", spl, "--earliest", "1792454400", "--latest", "1792713600",
                    "--chunk", "1d", "--out-dir", d / "export", "-f", "jsonl", "--poll", "1")
        self.run_py("network_feed.py", "merge", d / "export", "-o", d / "requests.jsonl")
        self.run_py(ROOT / "payload_analyzer" / "payload_analyzer.py", "pipeline", d / "requests.jsonl",
                    "-o", d / "analysis.json", isolated=True)
        self.run_py(ROOT / "payload_analyzer" / "report_builder.py", d / "analysis.json", "-o", d / "report.html",
                    isolated=True)
        self.run_py("network_feed.py", "iocs", d / "analysis.json", "-o", d / "findings.json")
        f = json.loads((d / "findings.json").read_text())
        srcs = {s["value"]: s for s in f["sources"]}
        self.assertEqual(set(srcs), {"203.0.113.7", "198.51.100.23", "192.0.2.200"})
        self.assertIn("sqli", srcs["203.0.113.7"]["categories"])
        self.assertTrue({"ssrf", "file_access", "rce"} <= set(srcs["198.51.100.23"]["categories"]))
        self.assertIn("cb.attacker.example", {c["value"] for c in f["callbacks"]})
        self.assertTrue((d / "report.html").stat().st_size > 10000)
        # attack map: levels from the payloads' phases and progression
        self.run_py("network_map.py", d / "analysis.json", "-o", d / "attack_map.html")
        import network_map
        m = network_map.build(d / "analysis.json")
        lv = {(p["src"], p["site"]): network_map.LEVELS[p["level"]][0] for p in m["pairs"]}
        self.assertEqual(lv[("203.0.113.7", "shop.example")], "sustained")      # 9 SQLi payloads, rising
        self.assertEqual(lv[("192.0.2.200", "shop.example")], "probing")        # the scanner
        self.assertEqual(lv[("198.51.100.23", "app.example")], "extraction")    # 2 payloads: too few for "in order"
        self.assertIn("sustained", (d / "attack_map.html").read_text(encoding="utf-8"))
        # credentials in URLs: full values in credentials.jsonl; in the report and findings never as plain text
        creds = [json.loads(l) for l in (d / "credentials.jsonl").read_text(encoding="utf-8").splitlines()]
        got = {(c["kind"], c["site"], c["user"], c["secret"]) for c in creds}
        self.assertIn(("url-credentials", "files.example", "svc_backup", "W1nter#Pass"), got)
        self.assertIn(("password", "shop.example", "jdoe", "Summer2026!"), got)
        login = next(c for c in creds if c["user"] == "jdoe")
        self.assertEqual((login["requests"], login["status"], login["src"]), (3, ["302"], ["10.20.30.40"]))
        report = (d / "report.html").read_text(encoding="utf-8")
        self.assertIn('id="s-cred"', report)
        self.assertEqual(report.count('href="#s-cred"'), 1)
        findings = json.loads((d / "findings.json").read_text(encoding="utf-8"))
        for secret in ("W1nter#Pass", "W1nter%23Pass", "Summer2026!", "Summer2026%21"):
            self.assertNotIn(secret, report.split("<!--voyager-credentials-->", 1)[1])   # the section and after
            self.assertNotIn(secret, json.dumps(findings["credentials"]))
        cbu = next(c for c in findings["callbacks"] if "svc_backup" in c["value"])   # Payload Analyzer's artifact
        self.assertEqual(cbu["display"], "http://svc_backup:W•••••••••s@192.168.10.5/admin")
        fc = {c["user"]: c for c in json.loads((d / "findings.json").read_text(encoding="utf-8"))["credentials"]}
        self.assertEqual((fc["jdoe"]["masked"], fc["jdoe"]["length"]), ("S•••••••••!", 11))
        self.assertEqual(fc["svc_backup"]["attack_sources"], ["198.51.100.23"])
        # running the findings step again replaces the section instead of adding a second one
        network_feed.iocs(d / "analysis.json", d / "findings.json")
        report = (d / "report.html").read_text(encoding="utf-8")
        self.assertEqual((report.count('id="s-cred"'), report.count('href="#s-cred"')), (1, 1))
        # sizes: from the export through requests.jsonl to each payload (by Payload Analyzer's line references)
        self.assertEqual(m["sizes"], {"req": True, "resp": True})
        us = {u["id"]: u for u in m["units"]}
        ext = [u for u in us.values() if u["site"] == "shop.example" and u["phase"] == "extraction" and u["statuses"] == ["200"]]
        probe = [u for u in us.values() if u["path"] == "/item"]
        self.assertTrue(ext and probe)
        self.assertTrue(all(u["resp_avg"] > 150000 and u["resp_ratio"] > 20 for u in ext), ext)
        self.assertTrue(all(3000 <= u["resp_avg"] <= 6000 and u["req_avg"] > 350 for u in probe), probe)
        self.assertTrue(all("bo" in e and "bi" in e for e in m["events"]))
        pair = next(p for p in m["pairs"] if (p["src"], p["site"]) == ("203.0.113.7", "shop.example"))
        self.assertGreater(pair["bo"], 3 * 150000)
        self.assertEqual(network_map.build(d / "analysis.json", requests=False)["sizes"], {"req": False, "resp": False})
        s = json.dumps(network_map.build(d / "analysis.json", sanitize=True))
        for leak in ("203.0.113", "198.51.100", "shop.example", "/search", "information_schema"):
            self.assertNotIn(leak, s)

    def test_gui_jobs(self):
        """The jobs the GUI starts (job runner + generated command lines), both modules at once."""
        import voyager_settings
        from app.services import workbench as wb
        d = Path(self.tmp.name, "gui")
        orig_settings, orig_root = voyager_settings.SETTINGS_PATH, wb.INV_ROOT
        voyager_settings.SETTINGS_PATH, wb.INV_ROOT = d / "settings.json", d / "investigations"
        os.environ["SPLUNK_COOKIE"] = "splunkd_8000=test"
        saved = {k: os.environ.pop(k, None) for k in ("SPLUNK_BASE", "SPLUNK_LOCALE", "SPLUNK_APP")}
        try:
            voyager_settings.save({"instances": [{"name": "mock", "base": self.base, "locale": "en-GB"}]})
            inv = wb.create_investigation("GUI test", "1792454400", "1792713600")
            jn = wb.start_network(inv["slug"], "index=web sourcetype=access_combined", chunk="1d")
            je = wb.start_entities(inv["slug"], ["203.0.113.7"], bin_min=1)
            deadline = time.time() + 300
            while time.time() < deadline:
                st = {j["id"]: j for j in wb.get_investigation(inv["slug"])["jobs"]}
                if all(st[j]["status"] in ("done", "failed", "interrupted") for j in (jn, je)):
                    break
                time.sleep(1)
            for j in (jn, je):
                self.assertEqual(st[j]["status"], "done", wb.read_log(inv["slug"], j))
            got = wb.get_investigation(inv["slug"])
            self.assertEqual({s["value"] for s in got["network"][0]["findings"]["sources"]},
                             {"203.0.113.7", "198.51.100.23", "192.0.2.200"})
            self.assertTrue(got["network"][0]["map"])
            self.assertEqual([s["value"] for s in got["entities"]["seeds"]], ["203.0.113.7"])
            self.assertTrue(got["entities"]["graph"])
            # re-analyse the finished export (as after updating Payload Analyzer): no Splunk step
            rep = wb.inv_dir(inv["slug"]) / "network" / jn / "report.html"
            rep.unlink()
            jr = wb.reanalyze_network(inv["slug"], jn)
            for _ in range(120):
                st = {j["id"]: j for j in wb.get_investigation(inv["slug"])["jobs"]}
                if st[jr]["status"] in ("done", "failed"):
                    break
                time.sleep(1)
            self.assertEqual(st[jr]["status"], "done", wb.read_log(inv["slug"], jr))
            self.assertNotIn("Splunk export", st[jr]["steps"])
            self.assertIn("Attack map", st[jr]["steps"])
            self.assertTrue(rep.is_file())
            with self.assertRaises(RuntimeError):            # belongs to its run
                wb.delete_job(inv["slug"], jr)
            # what the double check tells before each destructive action
            imp = wb.impact(inv["slug"], "delete_job", jn)
            self.assertEqual((imp["type"], imp["token"]), ("delete", "delete"))
            self.assertIn("Splunk export", imp["lines"][0])
            self.assertIn("1 re-analysis job(s)", imp["lines"][0])
            self.assertIn("report.html", " ".join(wb.impact(inv["slug"], "reanalyze", jn)["lines"]))
            self.assertIn("Resume", " ".join(wb.impact(inv["slug"], "stop", jn)["lines"]))
            reset = wb.impact(inv["slug"], "reset_range", values=["203.0.113.7", "new.example"], earliest="2026-10-01")
            self.assertEqual(len(reset["lines"]), 1)
            self.assertIn("203.0.113.7", reset["lines"][0])
            seed = wb.get_investigation(inv["slug"])["entities"]["seeds"][0]
            self.assertIsNone(wb.impact(inv["slug"], "reset_range", values=["203.0.113.7"],
                                        earliest=seed["earliest"], latest=seed["latest"]))
            wb.delete_job(inv["slug"], jn)                   # the run takes its re-analyses with it
            left = {j["id"] for j in wb.get_investigation(inv["slug"])["jobs"]}
            self.assertFalse({jn, jr} & left)
            self.assertFalse((wb.inv_dir(inv["slug"]) / "network" / jn).exists())
        finally:
            voyager_settings.SETTINGS_PATH, wb.INV_ROOT = orig_settings, orig_root
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v

    def test_keepalive(self):
        import voyager_settings
        from app.services import session as ss
        import app.routes.api as api
        orig = voyager_settings.SETTINGS_PATH
        voyager_settings.SETTINGS_PATH = Path(self.tmp.name, "ka_settings.json")
        saved = os.environ.pop("SPLUNK_BASE", None)
        try:
            voyager_settings.save({"instances": [{"name": "mock", "base": self.base}]})
            self.assertEqual(ss.keepalive_ping({"splunkd_8000": "x"}, "127.0.0.1"), ("ok", "tester"))
            self.assertEqual(ss.keepalive_ping({"splunkd_8000": "expired"}, "127.0.0.1")[0], "expired")
            voyager_settings.save({"instances": [{"name": "down", "base": "http://127.0.0.1:9"}]})
            self.assertEqual(ss.keepalive_ping({"splunkd_8000": "x"}, "127.0.0.1")[0], "error")
            # the loop: network error -> keeps going; expired -> stops and queues a reload of the keep-alive tab
            answers = iter([("error", "down"), ("ok", "tester"), ("expired", "HTTP 401")])
            calls, statuses = [], []
            fake_session = type("S", (), {"get_by_id": staticmethod(lambda i: {"id": i}),
                                          "update_status": staticmethod(lambda i, v: statuses.append(v))})
            fake_cookie = type("C", (), {"get_for_session": staticmethod(lambda i: {"splunkd_8000": "x"})})
            with unittest.mock.patch.object(ss, "keepalive_ping", lambda c, d: calls.append(1) or next(answers)), \
                 unittest.mock.patch.object(ss, "Session", fake_session), unittest.mock.patch.object(ss, "Cookie", fake_cookie), \
                 unittest.mock.patch.object(ss, "BEACON_INTERVAL", 0), unittest.mock.patch.object(ss, "KEEPALIVE_RETRY", 0):
                before = api._refresh["requested"]
                ss.active_beacons["d_1"] = True
                ss.session_beacon("d", 1)
            self.assertEqual(len(calls), 3)
            self.assertEqual(statuses, [True, False])
            self.assertGreater(api._refresh["requested"], before)
        finally:
            voyager_settings.SETTINGS_PATH = orig
            if saved is not None:
                os.environ["SPLUNK_BASE"] = saved

    def test_entity_mapper(self):
        case = Path(self.tmp.name, "case")
        for v in ("198.51.100.23", "cb.attacker.example"):
            self.run_py("pivot_graph.py", "seed", case, v, "--earliest", "1792454400", "--latest", "1792713600",
                        "--poll", "1")
        self.assertFalse([p for p in case.rglob("part-*") if p.suffix != ".zip"])   # every window compressed
        self.assertTrue(list(case.rglob("part-*.zip")))
        self.run_py("pivot_graph.py", "build", case, "-o", case / "graph.html", "--bin", "1")
        html = (case / "graph.html").read_text(encoding="utf-8")
        # the same graph from loose part files (unpacked) as from the zips
        import zipfile
        loose = Path(self.tmp.name, "case_loose")
        shutil.copytree(case, loose)
        for z in loose.rglob("part-*.zip"):
            with zipfile.ZipFile(z) as zz:
                zz.extractall(z.parent)
            z.unlink()
        self.run_py("pivot_graph.py", "build", loose, "-o", loose / "graph.html", "--bin", "1")
        strip = lambda h: re.sub(r'"generated":"[^"]*"|"case":"[^"]*"|"cases":\[[^\]]*\]', "", h)
        self.assertEqual(strip(html), strip((loose / "graph.html").read_text(encoding="utf-8")))
        self.assertIn("fw:traffic", html)
        self.assertIn("linux_secure", html)
        self.assertIn('"kind":"cooccur"', html)       # the two seeds appear in the same web request
        self.assertTrue((case / "graph_entities.csv").is_file())


if __name__ == "__main__":
    unittest.main()

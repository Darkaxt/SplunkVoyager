"""Voyager tests: python -m unittest discover -s tests   (Payload Analyzer has its own in payload_analyzer/tests)."""
import json
import os
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
                self.assertEqual(self.c.delete(f"/api/inv/{inv['slug']}").status_code, 200)
                self.assertFalse((Path(d) / inv["slug"]).exists())
                self.assertEqual(self.c.get(f"/investigations/{inv['slug']}").status_code, 404)
            finally:
                wb.INV_ROOT = orig


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
        self.assertEqual(set(srcs), {"203.0.113.7", "198.51.100.23"})
        self.assertIn("sqli", srcs["203.0.113.7"]["categories"])
        self.assertTrue({"ssrf", "file_access", "rce"} <= set(srcs["198.51.100.23"]["categories"]))
        self.assertIn("cb.attacker.example", {c["value"] for c in f["callbacks"]})
        self.assertTrue((d / "report.html").stat().st_size > 10000)

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
            self.assertEqual({s["value"] for s in got["network"][0]["findings"]["sources"]}, {"203.0.113.7", "198.51.100.23"})
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
            self.assertTrue(rep.is_file())
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
        self.run_py("pivot_graph.py", "build", case, "-o", case / "graph.html", "--bin", "1")
        html = (case / "graph.html").read_text(encoding="utf-8")
        self.assertIn("fw:traffic", html)
        self.assertIn("linux_secure", html)
        self.assertIn('"kind":"cooccur"', html)       # the two seeds appear in the same web request
        self.assertTrue((case / "graph_entities.csv").is_file())


if __name__ == "__main__":
    unittest.main()

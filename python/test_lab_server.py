import json
import os
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

TEST_DB = os.path.join(tempfile.gettempdir(), "test_appsec_lab_unit.db")
os.environ["APPSEC_DB_PATH"] = TEST_DB

from python import lab_server  # noqa: E402


class LabServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        lab_server.DB_PATH = TEST_DB
        lab_server.init_db(reset=True)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), lab_server.LabHandler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        if os.path.exists(TEST_DB):
            os.remove(TEST_DB)

    def post(self, path: str, body: dict) -> dict:
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def test_sqli_vulnerable_vs_patched(self) -> None:
        vuln = self.post("/py/lab/sqli", {"query": "' OR '1'='1", "mode": "vulnerable"})
        self.assertTrue(vuln["exploited"])
        self.assertGreater(len(vuln["rows"]), 1)

        patched = self.post("/py/lab/sqli", {"query": "' OR '1'='1", "mode": "patched"})
        self.assertFalse(patched["exploited"])
        self.assertEqual(len(patched["rows"]), 0)

    def test_xss_escaping_and_csp(self) -> None:
        vuln = self.post("/py/lab/xss", {"author": "eve", "comment": "<script>alert(1)</script>", "mode": "vulnerable"})
        self.assertTrue(vuln["exploited"])
        self.assertIn("<script>", vuln["renderedHtml"])

        patched = self.post("/py/lab/xss", {"author": "eve", "comment": "<script>alert(1)</script>", "mode": "patched"})
        self.assertFalse(patched["exploited"])
        self.assertIn("&lt;script&gt;", patched["renderedHtml"])
        self.assertIn("default-src 'self'", patched["cspHeader"])

    def test_idor_ownership_gate(self) -> None:
        vuln = self.post("/py/lab/idor", {"recordId": 102, "actingUserId": 1, "actingRole": "analyst", "mode": "vulnerable"})
        self.assertTrue(vuln["exploited"])
        self.assertEqual(vuln["httpStatus"], 200)

        patched = self.post("/py/lab/idor", {"recordId": 102, "actingUserId": 1, "actingRole": "analyst", "mode": "patched"})
        self.assertFalse(patched["exploited"])
        self.assertEqual(patched["httpStatus"], 403)


if __name__ == "__main__":
    unittest.main()

"""Native HTTP capture fixture; no target traffic or security verdicts."""
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[3]


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/close":
            self.close_connection = True
            return
        self.send_response(302)
        self.send_header("Set-Cookie", "fixture_one=one")
        self.send_header("Set-Cookie", "fixture_two=two")
        self.send_header("Location", "/offline-only")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


class NativeCaptureTest(unittest.TestCase):
    def test_actual_post_body_matches_server_observation(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        config = yaml.safe_load((ROOT / "tools/http-framework-test.yaml").read_text())
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "post.json"
            result = subprocess.run([sys.executable, *config["args"], "--url", f"http://127.0.0.1:{server.server_port}/fixture", "--method", "POST", "--data", "field=fixture%20value", "--capture-file", str(path)], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(path.read_text())
            self.assertEqual(base64.b64decode(data["request_body_base64"]), base64.b64decode(data["body_base64"]))
            self.assertEqual(data["method"], "POST")

    def test_native_request_failure_preserves_error_and_nonzero_exit(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(server.server_close)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        config = yaml.safe_load((ROOT / "tools/http-framework-test.yaml").read_text())
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "error.json"
            completed = subprocess.run([sys.executable, *config["args"], "--url", f"http://127.0.0.1:{server.server_port}/close", "--capture-file", str(path)], capture_output=True, text=True, timeout=20)
            self.assertNotEqual(completed.returncode, 0)
            data = json.loads(path.read_text())
            self.assertEqual(data["source"], "http-framework-test native request error")
            self.assertTrue(data["error_type"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_empty_body_and_duplicate_headers_are_preserved(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(server.server_close)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        config = yaml.safe_load((ROOT / "tools/http-framework-test.yaml").read_text())
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "native.json"
            url = f"http://127.0.0.1:{server.server_port}/non-root?test=1"
            completed = subprocess.run([sys.executable, *config["args"], "--url", url, "--capture-file", str(path), "--cookies", "fixture_capture=probe", "--repeat", "2"], capture_output=True, text=True, timeout=20)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(path.exists())
            for index in (1, 2):
                target = Path(temp) / f"native-{index}.json"
                data = json.loads(target.read_text())
                self.assertEqual(data["status_code"], 302)
                self.assertEqual(data["url"], url)
                self.assertEqual(data["input_url"], url)
                self.assertEqual(data["wire_request_target"], "/non-root?test=1")
                self.assertEqual(base64.b64decode(data["request_body_base64"]), b"")
                self.assertTrue(any("fixture_capture=probe" in [part.strip() for part in v.split(";")] for k, v in data["request_headers"] if k.lower() == "cookie"))
                self.assertEqual(base64.b64decode(data["body_base64"]), b"")
                self.assertEqual(data["body_length"], 0)
                self.assertEqual([v for k, v in data["headers"] if k.lower() == "set-cookie"], ["fixture_one=one", "fixture_two=two"])
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()

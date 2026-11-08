import hashlib
import http.server
import threading
import unittest

from reversetok import WreqClient


class _Handler(http.server.BaseHTTPRequestHandler):
    seen = {}

    def do_GET(self):
        type(self).seen = {name.lower(): value for name, value in self.headers.items()}
        payload = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        type(self).seen = {name.lower(): value for name, value in self.headers.items()}
        type(self).seen["body"] = body.decode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class WreqTransportTests(unittest.TestCase):
    def test_signed_request_uses_wreq_blocking_client(self):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = WreqClient({"deviceId": "0000000000000000001", "installId": "0000000000000000002"})
            response = client.get(f"http://127.0.0.1:{server.server_port}/signed?aid=1233", replay={"nowSeconds": 1793934086})
            self.assertEqual(response.status, 200)
            self.assertTrue(response.ok)
            self.assertEqual(response.text, "ok")
            for name in ("x-argus", "x-gorgon", "x-khronos", "x-ss-req-ticket", "x-ladon", "x-ss-stub"):
                self.assertIn(name, _Handler.seen)
            self.assertEqual(_Handler.seen["x-khronos"], "1793934086")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_post_sends_exact_body_and_custom_headers(self):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = WreqClient({"deviceId": "0000000000000000001", "installId": "0000000000000000002"})
            response = client.post(
                f"http://127.0.0.1:{server.server_port}/signed?aid=1233",
                headers={"content-type": "text/plain", "x-request-proof": "present"},
                body=b"probe",
                replay={"nowSeconds": 1793934086},
            )
            self.assertEqual(response.status, 200)
            self.assertEqual(response.text, "probe")
            self.assertEqual(_Handler.seen["body"], "probe")
            self.assertEqual(_Handler.seen["x-request-proof"], "present")
            expected_stub = hashlib.md5(b"probe").hexdigest().upper()
            self.assertEqual(_Handler.seen["x-ss-stub"], expected_stub)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()

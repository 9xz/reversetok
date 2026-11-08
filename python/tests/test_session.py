import http.client
import http.server
import threading
import unittest
from urllib.parse import urlsplit

from wreq import Proxy

from reversetok import MetaSecSigner, WreqSession


PERSONA = {
    "deviceId": "0000000000000000001",
    "installId": "0000000000000000002",
    "f34": "9066089097591521280",
    "f35": "13838013542538480364",
    "f36": "7678332264662476164",
}
REPLAY = {
    "nowSeconds": 1793934086,
    "nonce": 818642162,
    "rnd4Hex": "f1fb0209",
    "ladonRandom4Hex": "65743635",
    "headerHex": "ecc5582d37019c0318",
    "trailerHex": "48228a29a79e78e0800000f50d",
    "key4Hex": "ffffeff4",
}


class WreqSessionTests(unittest.TestCase):
    def test_session_keeps_cookies_and_proxy_while_signing_default_headers(self):
        target_seen = []

        class Target(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                target_seen.append((self.path, {name.lower(): value for name, value in self.headers.items()}))
                body = (self.headers.get("Cookie") if self.path.startswith("/next") else "ok") or ""
                body = body.encode()
                self.send_response(200)
                if self.path.startswith("/start"):
                    self.send_header("Set-Cookie", "flow=abc; Path=/; HttpOnly")
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Target)
        proxy_requests = []

        class ProxyHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.headers.get("Proxy-Authorization") != "Basic dXNlcjpwYXNz":
                    self.send_response(407)
                    self.send_header("Proxy-Authenticate", "Basic realm=test")
                    self.end_headers()
                    return
                destination = urlsplit(self.path)
                if destination.hostname != "127.0.0.1" or destination.port != target.server_port:
                    self.send_error(403)
                    return
                proxy_requests.append(destination.path)
                headers = {
                    name: value
                    for name, value in self.headers.items()
                    if name.lower() not in {"proxy-authorization", "proxy-connection", "connection"}
                }
                path = destination.path + (("?" + destination.query) if destination.query else "")
                connection = http.client.HTTPConnection(destination.hostname, destination.port, timeout=10)
                connection.request("GET", path, headers=headers)
                response = connection.getresponse()
                body = response.read()
                self.send_response(response.status)
                self.send_header("Content-Type", response.getheader("Content-Type") or "application/octet-stream")
                if response.getheader("Set-Cookie") is not None:
                    self.send_header("Set-Cookie", response.getheader("Set-Cookie"))
                self.send_header("X-Local-Proxy", "hit")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                connection.close()

            def log_message(self, *_args):
                pass

        proxy = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
        threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (target, proxy)]
        for thread in threads:
            thread.start()
        origin = f"http://127.0.0.1:{target.server_port}"
        session = None
        try:
            default_headers = {"x-common-params-v2": "aid=1233", "x-default-proof": "present"}
            url = f"{origin}/start?aid=1233"
            expected = MetaSecSigner(PERSONA).sign_request(url, headers=default_headers, **REPLAY)
            session = WreqSession(
                PERSONA,
                proxies=[Proxy.all(f"http://user:pass@127.0.0.1:{proxy.server_port}")],
                headers=default_headers,
            )
            first = session.get(url, replay=REPLAY)
            self.assertEqual(first.status, 200)
            self.assertEqual(first.headers.get("x-local-proxy"), "hit")
            self.assertEqual(target_seen[0][1]["x-argus"], expected["headers"]["X-Argus"])
            self.assertEqual(target_seen[0][1]["x-default-proof"], "present")
            self.assertNotIn("proxy-authorization", target_seen[0][1])

            second = session.get(f"{origin}/next?aid=1233", replay=REPLAY)
            self.assertEqual(second.status, 200)
            self.assertEqual(second.text, "flow=abc")
            self.assertEqual(session.get_cookies(origin)["flow"], "abc")
            self.assertEqual(proxy_requests, ["/start", "/next"])
            for _, headers in target_seen:
                for name in ("x-argus", "x-gorgon", "x-khronos", "x-ss-req-ticket", "x-ladon", "x-ss-stub"):
                    self.assertIn(name, headers)
            session.close()
            self.assertTrue(session.closed)
            with self.assertRaisesRegex(RuntimeError, "closed"):
                session.get(url)
        finally:
            if session is not None:
                session.close()
            proxy.shutdown()
            target.shutdown()
            proxy.server_close()
            target.server_close()
            for thread in threads:
                thread.join(timeout=5)

    def test_cookie_jars_are_isolated_and_clearable(self):
        first = WreqSession(PERSONA)
        second = WreqSession(PERSONA)
        try:
            first.set_cookie("flow", "abc", "https://example.com/path")
            self.assertEqual(first.get_cookies("https://example.com/next")["flow"], "abc")
            self.assertTrue(any(cookie.name == "flow" and cookie.value == "abc" for cookie in first.get_all_cookies()))
            self.assertEqual(second.get_cookies("https://example.com/next"), {})
            first.clear_cookies()
            self.assertEqual(first.get_cookies("https://example.com/next"), {})
        finally:
            first.close()
            second.close()


if __name__ == "__main__":
    unittest.main()

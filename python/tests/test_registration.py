import gzip
import http.server
import json
import threading
import unittest

from reversetok import MetaSecSigner, WreqSession, tt_decrypt_gzip
from reversetok.profiles import build_common_params, build_registration_header
from reversetok.registration import DeviceRegistrationClient, RegistrationResponseError
from python.tests.test_profiles import COMMON_OVERRIDES, PERSONA, REGISTRATION_OVERRIDES


REPLAY = {
    "nowSeconds": 1793934086,
    "nonce": 818642162,
    "rnd4Hex": "f1fb0209",
    "ladonRandom4Hex": "65743635",
    "headerHex": "ecc5582d37019c0318",
    "trailerHex": "48228a29a79e78e0800000f50d",
    "key4Hex": "ffffeff4",
}
COMMON_HEADERS = {
    "user-agent": "captured-registration-transport",
    "x-common-params-v2": "&captured=1",
}


class RegistrationHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        server = self.server
        server.request_count += 1
        body = self.rfile.read(int(self.headers["Content-Length"]))
        headers = {name.lower(): value for name, value in self.headers.items()}
        try:
            request_headers = {
                **COMMON_HEADERS,
                "content-type": "application/octet-stream;tt-data=a",
                "accept-encoding": "gzip",
            }
            expected = MetaSecSigner(server.persona).sign_request(
                server.origin + self.path,
                method="POST",
                headers=request_headers,
                body=body,
                **REPLAY,
            )
            for name, value in expected["headers"].items():
                if headers.get(name.lower()) != value:
                    raise AssertionError(f"signed header {name} did not match")
            envelope = json.loads(tt_decrypt_gzip(body))
            server.requests.append({"headers": headers, "envelope": envelope})
        except Exception as exc:
            server.errors.append(exc)

        response_body = json.dumps(server.response_payload, separators=(",", ":")).encode()
        if server.gzip_response:
            response_body = gzip.compress(response_body, mtime=0)
        self.send_response(server.response_status)
        self.send_header("Content-Type", "application/json")
        if server.gzip_response:
            self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(response_body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(response_body)

    def log_message(self, *_args):
        pass


class DeviceRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RegistrationHandler)
        self.server.origin = f"http://127.0.0.1:{self.server.server_port}"
        self.server.persona = dict(PERSONA)
        self.server.response_status = 200
        self.server.response_payload = {
            "device_id": 7370000000000000101,
            "install_id": "7370000000000000102",
        }
        self.server.gzip_response = False
        self.server.requests = []
        self.server.errors = []
        self.server.request_count = 0
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = self.server.origin + "/service/2/device_register/"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def register(self, persona=None):
        persona = dict(persona or PERSONA)
        self.server.persona = persona
        with WreqSession(persona) as session:
            client = DeviceRegistrationClient(
                session,
                persona,
                common_headers=COMMON_HEADERS,
                overrides=REGISTRATION_OVERRIDES,
                query_params=build_common_params(persona, COMMON_OVERRIDES),
                endpoint=self.endpoint,
            )
            return client.register(now_ms=1793934086123, replay=REPLAY)

    def test_encrypted_registration_round_trip_and_signed_headers(self):
        self.server.response_payload["device_id_str"] = "must-not-override-device-id"
        self.server.response_payload["device_token"] = "local-device-token"
        result = self.register()
        self.assertEqual(result, {
            "deviceId": "7370000000000000101",
            "installId": "7370000000000000102",
            "deviceToken": "local-device-token",
        })
        self.assertEqual(self.server.errors, [])
        self.assertEqual(len(self.server.requests), 1)
        request = self.server.requests[0]
        self.assertEqual(request["headers"]["content-type"], "application/octet-stream;tt-data=a")
        self.assertEqual(request["headers"]["accept-encoding"], "gzip")
        self.assertEqual(request["headers"]["x-common-params-v2"], "&captured=1")
        for name in ("x-argus", "x-gorgon", "x-khronos", "x-ladon", "x-ss-stub"):
            self.assertIn(name, request["headers"])
        self.assertEqual(request["envelope"], {
            "magic_tag": "ss_app_log",
            "header": build_registration_header(PERSONA, REGISTRATION_OVERRIDES),
            "time_sync": {},
            "_gen_time": 1793934086123,
        })

    def test_gzip_response_and_device_id_str_fallback(self):
        self.server.gzip_response = True
        self.server.response_payload = {
            "device_id_str": "7370000000000000201",
            "install_id": "7370000000000000202",
            "bd_did": "local-bd-did",
            "ssid": "local-ssid",
            "device_token": "local-token",
        }
        self.assertEqual(self.register(), {
            "deviceId": "7370000000000000201",
            "installId": "7370000000000000202",
            "bdDid": "local-bd-did",
            "ssid": "local-ssid",
            "deviceToken": "local-token",
        })
        self.assertEqual(self.server.errors, [])

    def test_invalid_schema_and_http_status_fail(self):
        self.server.response_payload = {"device_id": "7370000000000000301"}
        with self.assertRaisesRegex(RegistrationResponseError, "install_id"):
            self.register()
        self.server.response_status = 502
        with self.assertRaisesRegex(RuntimeError, "HTTP 502"):
            self.register()
        self.server.response_status = 200
        self.server.response_payload = {"device_id": "0", "install_id": "0"}
        with self.assertRaisesRegex(RegistrationResponseError, "placeholder identity"):
            self.register()

    def test_empty_identity_requires_explicit_registration_opt_in(self):
        empty = {**PERSONA, "deviceId": "", "installId": ""}
        with self.assertRaisesRegex(ValueError, "allowEmptyIdentity"):
            self.register(empty)
        self.assertEqual(self.server.request_count, 0)

        empty["allowEmptyIdentity"] = True
        result = self.register(empty)
        self.assertEqual(result["deviceId"], "7370000000000000101")
        self.assertEqual(self.server.errors, [])
        header = self.server.requests[0]["envelope"]["header"]
        self.assertNotIn("device_id", header)
        self.assertNotIn("install_id", header)


if __name__ == "__main__":
    unittest.main()

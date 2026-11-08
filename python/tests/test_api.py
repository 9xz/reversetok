import base64
import http.server
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient

from reversetok._native import native_version
from reversetok.api import ApiConfig, create_app, create_app_from_env
from reversetok.store import AttemptStore
from reversetok.ttencrypt import tt_decrypt_gzip
from python.tests.test_profiles import PERSONA, REGISTRATION_OVERRIDES
from python.tests.test_signing import NATIVE_TOKEN


class ApiSignupHandler(http.server.BaseHTTPRequestHandler):
    forms = []
    registration_bodies = []
    challenge = False

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        path = urlsplit(self.path).path
        if path == "/service/2/device_register/":
            type(self).registration_bodies.append(json.loads(tt_decrypt_gzip(body)))
            return self.respond({"device_id_str": "device-1", "install_id": "install-1"}, raw_response=True)
        fields = parse_qs(body.decode(), keep_blank_values=True)
        type(self).forms.append((path, fields))
        if path == "/passport/user/check_email_registered":
            return self.respond({"is_registered": 0, "need_verify_email": 0})
        if path in {"/passport/email/send_code/", "/passport/mobile/send_code/v1/"}:
            if type(self).challenge:
                return self.respond(
                    {"captcha": "raw-challenge-secret"},
                    code=1001,
                    description="challenge required",
                )
            return self.respond({"has_account": False, "retry_time": 30}, cookie=True)
        if path in {"/passport/email/check_code/", "/passport/mobile/check_code/"}:
            return self.respond({"ticket": "opaque-ticket"})
        if path in {
            "/passport/email/register/v2/",
            "/passport/email/register_verify_login/",
            "/passport/mobile/sms_login_continue/",
            "/passport/username/register/",
        }:
            return self.respond({"uid": "new-user"}, token=True)
        if path in {"/passport/mobile/sms_login/", "/passport/mobile/sms_login_only/"}:
            return self.respond({"sms_code_key": "continue-key"})
        if path == "/tiktok/v1/calculate/age/":
            return self.respond({"age": 26, "appeal_url": "", "verification_reason": ""})
        if path == "/aweme/v3/verification/age/":
            return self.respond({"is_prompt": True})
        if path == "/passport/password/set/":
            return self.respond({"accepted": True})
        if path == "/passport/login_name/check/":
            return self.respond({"login_name": fields["login_name"][0], "recommended_login_names": ["alt_handle"]})
        if path in {"/passport/login_name/register/", "/passport/login_name/update/"}:
            return self.respond({"login_name": fields["login_name"][0]})
        if path == "/aweme/v1/commit/user/":
            return self.respond(
                {
                    "status_code": 0,
                    "status_msg": "",
                    "user": {
                        "nickname": fields.get("nickname", ["Test"])[0],
                        "signature": fields.get("signature", [""])[0],
                        "unique_id": fields.get("unique_id", ["handle"])[0],
                    },
                },
                raw_response=True,
            )
        if path == "/passport/account/info/v2/":
            return self.respond({"user_id_str": "7705855766996042766", "screen_name": "custom_handle"})
        return self.respond({}, code=404, description="not found")

    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/tiktok/v1/calculate/age/":
            return self.respond({"age": 26, "appeal_url": "", "verification_reason": ""})
        if parsed.path == "/passport/token/beat/v2/":
            return self.respond({"beat": "ok"}, token=True)
        return self.respond({}, code=404, description="not found")
    def respond(self, data, code=0, description="success", token=False, cookie=False, raw_response=False):
        payload = data if raw_response else {"message": description, "data": data}
        status = 200
        if code:
            payload["error_code"] = code
            payload["description"] = description
        if code == 404:
            status = 404
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        if token:
            self.send_header("X-tt-token", "session-token")
        if cookie:
            self.send_header("Set-Cookie", "flow=abc; Path=/; HttpOnly")
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *_args):
        pass


class ApiTests(unittest.TestCase):
    def setUp(self):
        ApiSignupHandler.forms = []
        ApiSignupHandler.registration_bodies = []
        ApiSignupHandler.challenge = False
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ApiSignupHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "attempts.sqlite"
        self.store = AttemptStore(self.db_path, bytes(range(32)))
        self.config = ApiConfig(
            api_key="test-api-key",
            persona={"deviceId": "1", "installId": "2"},
            base_url=self.base_url,
            attempt_ttl_seconds=60,
        )
        self.client = TestClient(create_app(self.store, self.config))
        self.auth = {"Authorization": "Bearer test-api-key"}

    def tearDown(self):
        self.client.close()
        self.store.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.tempdir.cleanup()

    def create_signup(self, key="create-1", password="create-password-secret"):
        response = self.client.post(
            "/v1/signups",
            headers={**self.auth, "X-Idempotency-Key": key},
            json={
                "method": "email",
                "email": "new@example.com",
                "code_type": 6,
                "password": password,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")
        return response

    def ciphertext(self):
        with closing(sqlite3.connect(self.db_path)) as connection:
            rows = connection.execute("SELECT ciphertext FROM attempts").fetchall()
        return b"".join(bytes(row[0]) for row in rows)

    def test_health_requires_auth_and_disables_docs(self):
        missing = self.client.get("/health")
        wrong = self.client.get("/health", headers={"Authorization": "Bearer wrong"})
        healthy = self.client.get("/health", headers=self.auth)
        docs = self.client.get("/docs", headers=self.auth)

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 401)
        self.assertEqual(healthy.status_code, 200)
        self.assertEqual(
            healthy.json(), {"status": "ok", "native_version": native_version()}
        )
        self.assertEqual(healthy.headers["cache-control"], "no-store")
        self.assertEqual(docs.status_code, 404)

    def test_email_flow_hides_secrets_and_encrypts_snapshot(self):
        created = self.create_signup()
        attempt_id = created.json()["id"]
        self.assertEqual(created.json()["status"], "needs_otp")
        self.assertEqual(created.json()["nextAction"], "submit_otp")

        otp = self.client.post(
            f"/v1/signups/{attempt_id}/otp",
            headers=self.auth,
            json={"code": "654321"},
        )
        self.assertEqual(otp.status_code, 200, otp.text)
        self.assertEqual(otp.json()["status"], "verified")

        completed = self.client.post(
            f"/v1/signups/{attempt_id}/password",
            headers=self.auth,
            json={"password": "completion-password-secret"},
        )
        self.assertEqual(completed.status_code, 200, completed.text)
        self.assertEqual(completed.json()["status"], "completed")
        loaded = self.client.get(f"/v1/signups/{attempt_id}", headers=self.auth)
        self.assertEqual(loaded.status_code, 200)
        self.assertEqual(loaded.json()["id"], attempt_id)
        self.assertEqual(loaded.json()["status"], "completed")

        for response in (created, otp, completed, loaded):
            for secret in (
                "create-password-secret",
                "completion-password-secret",
                "654321",
                "opaque-ticket",
                "session-token",
                "flow=abc",
            ):
                self.assertNotIn(secret, response.text)
            self.assertNotIn("password", response.json())
            self.assertNotIn("sessionToken", response.json())
        for secret in (
            b"create-password-secret",
            b"completion-password-secret",
            b"654321",
            b"opaque-ticket",
            b"session-token",
            b"abc",
        ):
            self.assertNotIn(secret, self.ciphertext())

        registration = next(
            fields
            for path, fields in ApiSignupHandler.forms
            if path == "/passport/email/register/v2/"
        )
        from reversetok.signup import mix_encode
        self.assertEqual(registration["code"], [mix_encode("654321")])
        self.assertEqual(registration["password"], [mix_encode("completion-password-secret")])

    def test_idempotent_create_returns_existing_without_replaying_remote_call(self):
        first = self.create_signup(key="same-request")
        second = self.create_signup(key="same-request", password="different-secret")

        self.assertEqual(first.json()["id"], second.json()["id"])
        self.assertEqual(first.json()["created_at"], second.json()["created_at"])
        send_code_calls = [
            fields
            for path, fields in ApiSignupHandler.forms
            if path == "/passport/email/send_code/"
        ]
        self.assertEqual(len(send_code_calls), 1)

    def test_cancel_delete_and_missing_attempt(self):
        attempt_id = self.create_signup(key="cancel-request").json()["id"]
        cancelled = self.client.post(
            f"/v1/signups/{attempt_id}/cancel", headers=self.auth
        )
        self.assertEqual(cancelled.status_code, 200)
        self.assertEqual(cancelled.json()["status"], "cancelled")
        conflict = self.client.post(
            f"/v1/signups/{attempt_id}/otp",
            headers=self.auth,
            json={"code": "123456"},
        )
        self.assertEqual(conflict.status_code, 409)
        deleted = self.client.delete(f"/v1/signups/{attempt_id}", headers=self.auth)
        self.assertEqual(deleted.status_code, 204)
        missing = self.client.get(f"/v1/signups/{attempt_id}", headers=self.auth)
        self.assertEqual(missing.status_code, 404)

        unknown = self.client.get("/v1/signups/not-present", headers=self.auth)
        self.assertEqual(unknown.status_code, 404)

    def test_expired_attempt_returns_410(self):
        created = self.create_signup(key="expiring-request").json()
        with patch("reversetok.store.time.time", return_value=created["expires_at"]):
            response = self.client.get(
                f"/v1/signups/{created['id']}", headers=self.auth
            )
        self.assertEqual(response.status_code, 410)
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_signup_and_validation_errors_do_not_echo_sensitive_data(self):
        ApiSignupHandler.challenge = True
        challenge = self.client.post(
            "/v1/signups",
            headers={**self.auth, "X-Idempotency-Key": "challenge-request"},
            json={"method": "email", "email": "new@example.com", "code_type": 6},
        )
        self.assertEqual(challenge.status_code, 422)
        self.assertEqual(challenge.json()["next_action"], "needs_challenge")
        self.assertNotIn("raw-challenge-secret", challenge.text)

        invalid = self.client.post(
            "/v1/signups",
            headers={**self.auth, "X-Idempotency-Key": "invalid-request"},
            json={
                "method": "email",
                "email": "new@example.com",
                "password": "validation-password-secret",
            },
        )
        self.assertEqual(invalid.status_code, 400)
        self.assertNotIn("validation-password-secret", invalid.text)

    def test_rate_and_content_length_limits(self):
        limited = TestClient(
            create_app(
                self.store,
                ApiConfig(
                    api_key="test-api-key",
                    persona=self.config.persona,
                    base_url=self.base_url,
                    rate_limit_per_minute=1,
                ),
            )
        )
        try:
            self.assertEqual(limited.get("/health", headers=self.auth).status_code, 200)
            self.assertEqual(limited.get("/health", headers=self.auth).status_code, 429)
        finally:
            limited.close()

        small_body = TestClient(
            create_app(
                self.store,
                ApiConfig(
                    api_key="test-api-key",
                    persona=self.config.persona,
                    base_url=self.base_url,
                    max_body_bytes=16,
                ),
            )
        )
        try:
            response = small_body.post(
                "/v1/signups",
                headers={**self.auth, "X-Idempotency-Key": "large-request"},
                json={"method": "email", "email": "new@example.com", "code_type": 6},
            )
            self.assertEqual(response.status_code, 413)
            self.assertEqual(response.headers["cache-control"], "no-store")
        finally:
            small_body.close()

    def test_alternate_email_and_mobile_completion_routes(self):
        email_id = self.create_signup(key="alternate-email").json()["id"]
        otp = self.client.post(f"/v1/signups/{email_id}/otp", headers=self.auth, json={"code": "123456"})
        self.assertEqual(otp.status_code, 200)
        completed = self.client.post(f"/v1/signups/{email_id}/email-verify-login", headers=self.auth)
        self.assertEqual(completed.status_code, 200, completed.text)
        self.assertEqual(completed.json()["status"], "completed")

        created = self.client.post(
            "/v1/signups",
            headers={**self.auth, "X-Idempotency-Key": "alternate-mobile"},
            json={"method": "mobile", "mobile": "+15550001111", "code_type": 6},
        )
        self.assertEqual(created.status_code, 200, created.text)
        mobile_id = created.json()["id"]
        completed = self.client.post(
            f"/v1/signups/{mobile_id}/mobile-login-only",
            headers=self.auth,
            json={"code": "123456", "birthday": "1999-05-14", "carrier_region": "US"},
        )
        self.assertEqual(completed.status_code, 200, completed.text)
        self.assertEqual(completed.json()["status"], "completed")
        checked = self.client.post(
            f"/v1/signups/{mobile_id}/login-name/check",
            headers=self.auth,
            json={"login_name": "candidate_handle"},
        )
        self.assertEqual(checked.status_code, 200, checked.text)
        self.assertTrue(checked.json()["loginNameAvailable"])
        registered = self.client.post(
            f"/v1/signups/{mobile_id}/login-name/register",
            headers=self.auth,
            json={"login_name": "registered_handle", "is_from_nickname": True},
        )
        self.assertEqual(registered.status_code, 200, registered.text)
        self.assertEqual(registered.json()["loginName"], "registered_handle")
        updated_name = self.client.post(
            f"/v1/signups/{mobile_id}/login-name/update",
            headers=self.auth,
            json={"login_name": "custom_handle"},
        )
        self.assertEqual(updated_name.status_code, 200, updated_name.text)
        self.assertEqual(updated_name.json()["uniqueId"], "custom_handle")
        profile = self.client.post(
            f"/v1/signups/{mobile_id}/profile",
            headers=self.auth,
            json={"nickname": "Display Name", "signature": "Bio text"},
        )
        self.assertEqual(profile.status_code, 200, profile.text)
        self.assertEqual(profile.json()["nickname"], "Display Name")
        beat = self.client.post(
            f"/v1/signups/{mobile_id}/token-beat",
            headers=self.auth,
            json={"scene": "boot", "first_beat": True},
        )
        self.assertEqual(beat.status_code, 200, beat.text)
        self.assertEqual(beat.json()["tokenBeatScene"], "boot")
        info = self.client.post(
            f"/v1/signups/{mobile_id}/account-info",
            headers=self.auth,
            json={"scene": "login"},
        )
        self.assertEqual(info.status_code, 200, info.text)
        self.assertEqual(info.json()["accountUserId"], "7705855766996042766")
        paths = [path for path, _ in ApiSignupHandler.forms]
        self.assertIn("/passport/mobile/sms_login_only/", paths)
        self.assertIn("/passport/mobile/sms_login_continue/", paths)
        self.assertIn("/passport/login_name/check/", paths)
        self.assertIn("/passport/login_name/register/", paths)
        self.assertIn("/passport/login_name/update/", paths)
        self.assertIn("/aweme/v1/commit/user/", paths)
        self.assertIn("/passport/account/info/v2/", paths)
    def test_device_registration_route_is_encrypted_and_idempotent(self):
        app = create_app(
            self.store,
            ApiConfig(
                api_key="test-api-key",
                persona=PERSONA,
                base_url=self.base_url,
                registration_endpoint=f"{self.base_url}/service/2/device_register/",
                registration_overrides=REGISTRATION_OVERRIDES,
            ),
        )
        client = TestClient(app)
        try:
            response = client.post(
                "/v1/device-registrations",
                headers={**self.auth, "X-Idempotency-Key": "registration-1"},
                json={"common_headers": {"x-common-params-v2": "&captured=1"}},
            )
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["deviceId"], "device-1")
            self.assertEqual(response.json()["installId"], "install-1")
            duplicate = client.post(
                "/v1/device-registrations",
                headers={**self.auth, "X-Idempotency-Key": "registration-1"},
                json={},
            )
            self.assertEqual(duplicate.status_code, 200)
            self.assertEqual(duplicate.json()["id"], response.json()["id"])
            self.assertEqual(len(ApiSignupHandler.registration_bodies), 1)
            envelope = ApiSignupHandler.registration_bodies[0]
            self.assertEqual(envelope["magic_tag"], "ss_app_log")
            self.assertEqual(envelope["header"]["aid"], "1233")
            self.assertEqual(envelope["time_sync"], {})
        finally:
            client.close()

    def test_offline_signing_route_uses_native_fixture(self):
        from python.tests.test_signing import SigningTests

        fixture = SigningTests()
        fixture.setUp()
        response = self.client.post(
            "/v1/sign",
            headers=self.auth,
            json={
                "url": fixture.url,
                "persona": fixture.signer.persona,
                "headers": {},
                "bodyBase64": "",
                "replay": fixture.options,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["headers"]["X-Argus"], NATIVE_TOKEN)
        self.assertEqual(response.json()["headers"]["X-Ss-Req-Ticket"], "1793934086000")

    def test_environment_configuration(self):
        state_path = Path(self.tempdir.name) / "from-env.sqlite"
        environment = {
            "REVERSETOK_API_KEY": "environment-api-key",
            "REVERSETOK_STATE_KEY": base64.b64encode(bytes(range(32))).decode(),
            "REVERSETOK_STATE_PATH": str(state_path),
            "REVERSETOK_PERSONA_JSON": json.dumps(self.config.persona),
            "REVERSETOK_API_BASE_URL": self.base_url,
        }
        with patch.dict(os.environ, environment, clear=False):
            app = create_app_from_env()
        try:
            self.assertEqual(app.state.api_config.api_key, "environment-api-key")
            self.assertEqual(app.state.api_config.base_url, self.base_url)
            self.assertEqual(app.state.attempt_store._path, state_path)
        finally:
            app.state.attempt_store.close()

        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "REVERSETOK_API_KEY"):
                create_app_from_env()


if __name__ == "__main__":
    unittest.main()

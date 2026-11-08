import http.server
import json
import threading
import unittest
from urllib.parse import parse_qs, urlsplit

from reversetok import WreqSession
from reversetok.session_state import restore_cookie_jar
from reversetok.signup import SignupClient, SignupError, mix_decode, mix_encode


class SignupHandler(http.server.BaseHTTPRequestHandler):
    forms = []
    queries = []
    missing_token = False
    challenge = False

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        fields = parse_qs(self.rfile.read(length).decode(), keep_blank_values=True)
        path = urlsplit(self.path).path
        type(self).forms.append((path, fields, {name.lower(): value for name, value in self.headers.items()}))
        if path == "/passport/user/check_email_registered":
            return self.respond({"is_registered": 0, "need_verify_email": 0})
        if path in {"/passport/email/send_code/", "/passport/mobile/send_code/v1/"}:
            if type(self).challenge:
                return self.respond({"captcha": "required", "error_code": 1001, "description": "challenge required"}, code=1001)
            return self.respond({"has_account": False, "retry_time": 30}, cookie=True)
        if path in {"/passport/email/check_code/", "/passport/mobile/check_code/"}:
            return self.respond({"ticket": "opaque-ticket"})
        if path in {
            "/passport/email/register/v2/",
            "/passport/email/register_verify_login/",
            "/passport/mobile/sms_login_continue/",
            "/passport/username/register/",
        }:
            return self.respond({"uid": "new-user"}, token=not type(self).missing_token)
        if path in {"/passport/mobile/sms_login/", "/passport/mobile/sms_login_only/"}:
            return self.respond({"sms_code_key": "continue-key"})
        if path == "/aweme/v3/verification/age/":
            return self.respond({
                "is_prompt": True,
                "register_age_gate_post_action": 1,
                "age_gate_post_action": 2,
                "is_mixed_age": False,
                "supplement_action": 3,
                "need_screen_time_reminder": False,
            })
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
        return self.respond({"description": "not found"}, code=404)

    def do_GET(self):
        parsed = urlsplit(self.path)
        type(self).queries.append((parsed.path, parse_qs(parsed.query)))
        if parsed.path == "/tiktok/v1/calculate/age/":
            return self.respond({"age": 26, "appeal_url": "", "verification_reason": ""})
        if parsed.path == "/passport/token/beat/v2/":
            return self.respond({"beat": "ok"}, token=True)
        return self.respond({"description": "not found"}, code=404)

    def respond(self, data, code=0, token=False, cookie=False, raw_response=False):
        if raw_response:
            payload = data
            status = 200
        elif code == 404:
            payload = {"error_code": code, "description": data["description"], "data": data}
            status = 404
        else:
            payload = {"message": "error" if code else "success", "data": data}
            status = 200
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        if token:
            import base64
            self.send_header("X-tt-token", "session-token")
            server_data = json.dumps({
                "tickets": [
                    {
                        "ticket": "tg-ticket-1",
                        "ts_sign": json.dumps({"ts_sign": "tee", "ts_sign_ree": "ree-ts-sig"}),
                    }
                ]
            }).encode()
            self.send_header("tt-ticket-guard-server-data", base64.b64encode(server_data).decode())
            self.send_header("Set-Cookie", "flow=abc; Path=/; HttpOnly")
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *_args):
        pass


class SignupTests(unittest.TestCase):
    def setUp(self):
        SignupHandler.forms = []
        SignupHandler.queries = []
        SignupHandler.missing_token = False
        SignupHandler.challenge = False
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), SignupHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"
        self.persona = {"deviceId": "1", "installId": "2"}

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def client(self, snapshot=None):
        session = WreqSession(self.persona)
        if snapshot is not None:
            restore_cookie_jar(session.cookie_jar, snapshot["cookies"])
        return SignupClient(session, base_url=self.base_url, state=snapshot["state"] if snapshot else None)

    def test_email_signup_survives_restart_and_hides_secrets(self):
        client = self.client()
        self.assertEqual(client.start_email("new@example.com", 6, password="secret")["nextAction"], "submit_otp")
        client = self.client(client.snapshot())
        self.assertEqual(client.submit_otp("123456")["nextAction"], "complete")
        client = self.client(client.snapshot())
        public = client.complete_email()
        self.assertEqual(public["status"], "completed")
        self.assertNotIn("sessionToken", public)
        self.assertNotIn("password", public)
        self.assertNotIn("otp", public)
        self.assertNotIn("ticket", public)
        register = next(fields for path, fields, _ in SignupHandler.forms if path == "/passport/email/register/v2/")
        self.assertEqual(register["code"], [mix_encode("123456")])
        self.assertEqual(register["password"], [mix_encode("secret")])
        self.assertEqual(mix_decode(register["password"][0]), "secret")
        check_code = next(fields for path, fields, _ in SignupHandler.forms if path == "/passport/email/check_code/")
        self.assertEqual(check_code["type"], [mix_encode("6")])
        for path, _, headers in SignupHandler.forms:
            for name in ("x-argus", "x-gorgon", "x-khronos", "x-ss-req-ticket", "x-ladon", "x-ss-stub"):
                self.assertIn(name, headers, path)
        self.assertEqual(client.snapshot()["cookies"][0]["name"], "flow")

    def test_mobile_signup_uses_ticket_and_continuation(self):
        client = self.client()
        client.start_mobile("+15550001111", 6)
        client.submit_otp("123456")
        public = client.complete_mobile()
        self.assertEqual(public["status"], "completed")
        paths = [path for path, _, _ in SignupHandler.forms]
        self.assertIn("/passport/mobile/sms_login/", paths)
        self.assertIn("/passport/mobile/sms_login_continue/", paths)
        login = next(fields for path, fields, _ in SignupHandler.forms if path == "/passport/mobile/sms_login/")
        self.assertEqual(login["not_login_ticket"], ["opaque-ticket"])
        continuation = next(fields for path, fields, _ in SignupHandler.forms if path == "/passport/mobile/sms_login_continue/")
        self.assertEqual(continuation["sms_code_key"], [mix_encode("continue-key")])
        send_code = next(fields for path, fields, _ in SignupHandler.forms if path == "/passport/mobile/send_code/v1/")
        self.assertEqual(send_code["mobile"], [mix_encode("+15550001111")])
        self.assertEqual(send_code["type"], [mix_encode("6")])
        self.assertEqual(send_code["unbind_exist"], [mix_encode("0")])
        self.assertEqual(send_code["is6Digits"], ["1"])
        self.assertEqual(send_code["account_sdk_source"], ["app"])
        self.assertEqual(send_code["multi_login"], ["1"])

    def test_age_username_and_password_steps(self):
        client = self.client()
        age = client.submit_birthday("2000-01-01", update_birthdate_type=1, session_register_type=2)
        self.assertEqual(age["age"], 26)
        verification = client.verify_age(
            "2000-01-01",
            update_birthdate_type=1,
            session_registered=0,
            birthday_confidence=100,
        )
        self.assertTrue(verification["isPrompt"])
        self.assertEqual(verification["registerAgeGatePostAction"], 1)
        self.assertEqual(client.register_username("newuser", "secret")["status"], "completed")
        self.assertEqual(client.set_password("secret")["status"], "completed")
        checked = client.check_login_name("candidate_handle")
        self.assertTrue(checked["loginNameAvailable"])
        self.assertEqual(checked["recommendedLoginNames"], ["alt_handle"])
        registered_name = client.register_login_name("registered_handle", is_from_nickname=True)
        self.assertEqual(registered_name["loginName"], "registered_handle")
        updated_name = client.update_login_name("custom_handle")
        self.assertEqual(updated_name["uniqueId"], "custom_handle")
        profile = client.commit_user_profile(nickname="Display Name", signature="Bio text", unique_id="custom_handle")
        self.assertEqual(profile["nickname"], "Display Name")
        self.assertEqual(profile["signature"], "Bio text")
        beat = client.token_beat(scene="boot", first_beat=True)
        self.assertEqual(beat["tokenBeatScene"], "boot")
        info = client.get_account_info(scene="login")
        self.assertEqual(info["accountUserId"], "7705855766996042766")
        self.assertEqual(info["screenName"], "custom_handle")
        commit_headers = next(headers for path, _, headers in SignupHandler.forms if path == "/aweme/v1/commit/user/")
        self.assertEqual(commit_headers["x-tt-token"], "session-token")
        self.assertEqual(commit_headers["tt-ticket-guard-version"], "3")
        self.assertIn("tt-ticket-guard-public-key", commit_headers)
        self.assertIn("tt-ticket-guard-client-data", commit_headers)
        query = SignupHandler.queries[0][1]
        self.assertEqual(query["birthday"], ["2000-01-01"])
        beat_query = next(q for p, q in SignupHandler.queries if p == "/passport/token/beat/v2/")
        self.assertEqual(beat_query["scene"], ["boot"])
        self.assertEqual(beat_query["first_beat"], ["true"])
    def test_missing_session_token_and_challenge_fail_cleanly(self):
        SignupHandler.missing_token = True
        client = self.client()
        client.start_email("new@example.com", 6, password="secret")
        client.submit_otp("123456")
        with self.assertRaisesRegex(SignupError, "x-tt-token"):
            client.complete_email()

        SignupHandler.challenge = True
        with self.assertRaises(SignupError) as caught:
            self.client().start_email("new@example.com", 6)
        self.assertEqual(caught.exception.next_action, "needs_challenge")


if __name__ == "__main__":
    unittest.main()

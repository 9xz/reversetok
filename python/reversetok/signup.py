"""Resumable TikTok email and mobile signup flows."""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import time
from typing import Any, Mapping
from urllib.parse import urlencode, urlsplit

from .profiles import with_common_params
from .session_state import dump_cookie_jar
from .wreq_client import WreqResponse, WreqSession

_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A = _P256_P - 3
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def _p256_add(p1: tuple[int, int] | None, p2: tuple[int, int] | None) -> tuple[int, int] | None:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % _P256_P == 0:
            return None
        lam = (3 * x1 * x1 + _P256_A) * pow(2 * y1, -1, _P256_P) % _P256_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P256_P) % _P256_P
    x3 = (lam * lam - x1 - x2) % _P256_P
    y3 = (lam * (x1 - x3) - y1) % _P256_P
    return x3, y3


def _p256_mul(k: int, point: tuple[int, int] = _P256_G) -> tuple[int, int]:
    result: tuple[int, int] | None = None
    addend: tuple[int, int] | None = point
    while k:
        if k & 1:
            result = _p256_add(result, addend)
        addend = _p256_add(addend, addend)
        k >>= 1
    assert result is not None
    return result


def _der_int(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 8) // 8 or 1, "big")
    return b"\x02" + bytes([len(raw)]) + raw


def _p256_keypair(priv_hex: str | None = None) -> tuple[str, str]:
    if priv_hex:
        d = int(priv_hex, 16)
    else:
        d = int.from_bytes(os.urandom(32), "big") % (_P256_N - 1) + 1
        priv_hex = f"{d:064x}"
    x, y = _p256_mul(d)
    pub_uncompressed = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    return priv_hex, base64.b64encode(pub_uncompressed).decode("ascii")


def _p256_sign_base64(priv_hex: str, message: bytes) -> str:
    d = int(priv_hex, 16)
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    while True:
        k = int.from_bytes(os.urandom(32), "big") % (_P256_N - 1) + 1
        x1, _ = _p256_mul(k)
        r = x1 % _P256_N
        if r == 0:
            continue
        s = pow(k, -1, _P256_N) * (z + r * d) % _P256_N
        if s != 0:
            break
    body = _der_int(r) + _der_int(s)
    der = b"\x30" + bytes([len(body)]) + body
    return base64.b64encode(der).decode("ascii")


def mix_encode(value: str) -> str:
    return bytes(byte ^ 5 for byte in value.encode("utf-8")).hex()


def mix_decode(value: str) -> str:
    return bytes(byte ^ 5 for byte in bytes.fromhex(value)).decode("utf-8")


class SignupError(RuntimeError):
    def __init__(self, message: str, *, code: Any = None, data: Any = None, next_action: str = "failed"):
        super().__init__(message)
        self.code = code
        self.data = data
        self.next_action = next_action


class SignupClient:
    def __init__(
        self,
        session: WreqSession,
        *,
        base_url: str = "https://api16-normal-c-alisg.tiktokv.com",
        state: Mapping[str, Any] | None = None,
        common_headers: Mapping[str, str] | None = None,
        query_params: Mapping[str, Any] | None = None,
    ):
        self.session = session
        self.base_url = base_url.rstrip("/")
        self.state = dict(state or {"status": "new", "nextAction": "start"})
        self.origin = self.base_url
        self.common_headers = dict(common_headers or {})
        self.query_params = dict(query_params or {})

    def snapshot(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "cookies": dump_cookie_jar(self.session.cookie_jar, [self.origin]),
        }

    def public_state(self) -> dict[str, Any]:
        fields = (
            "status", "nextAction", "method", "email", "mobile", "hasAccount", "retryTime",
            "age", "appealUrl", "verificationReason", "isPrompt", "registerAgeGatePostAction",
            "ageGatePostAction", "isMixedAge", "supplementAction", "needScreenTimeReminder",
            "loginName", "loginNameAvailable", "recommendedLoginNames", "nickname",
            "signature", "avatarUri", "uniqueId", "accountUserId", "screenName", "tokenBeatScene",
        )
        return {key: self.state[key] for key in fields if key in self.state}

    def _decode(self, response: WreqResponse) -> dict[str, Any]:
        if not 200 <= response.status < 300:
            raise SignupError(f"HTTP {response.status}", code=response.status, next_action="failed")
        raw = response.text.encode()
        encoding = response.headers.get("content-encoding", "").lower()
        if encoding == "gzip":
            raw = gzip.decompress(raw)
        try:
            result = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SignupError("invalid JSON response", data=error, next_action="failed") from error
        if not isinstance(result, dict):
            raise SignupError("response root must be an object", next_action="failed")
        data = result.get("data")
        data_dict = data if isinstance(data, dict) else {}
        message = result.get("message")
        code = result.get("error_code", result.get("code"))
        if code in (None, 0, "0"):
            code = data_dict.get("error_code", data_dict.get("code"))
        status_code = result.get("status_code")
        if status_code not in (None, 0, "0") and code in (None, 0, "0"):
            raise SignupError(
                str(result.get("status_msg") or result.get("message") or f"aweme error {status_code}"),
                code=status_code,
                data=result,
                next_action="failed",
            )
        if (message in {"error", "exception"} or code not in (None, 0, "0")) and not data_dict.get("sms_code_key"):
            challenge_keys = {
                "captcha",
                "recaptcha",
                "recaptcha_token",
                "shark_ticket",
                "verify_ticket",
                "verify_center_decision_conf",
            }
            next_action = "needs_challenge" if challenge_keys.intersection(data_dict) else "failed"
            description = (
                data_dict.get("description")
                or result.get("description")
                or data_dict.get("message")
                or (message if message not in {None, "error", "exception"} else None)
                or f"signup error {code}"
            )
            raise SignupError(
                str(description),
                code=code,
                data=data,
                next_action=next_action,
            )
        return result

    def _ensure_ticket_guard_key(self) -> tuple[str, str]:
        priv_hex = self.state.get("ticketGuardPrivateKey")
        pub_b64 = self.state.get("ticketGuardPublicKey")
        if not priv_hex or not pub_b64:
            priv_hex, pub_b64 = _p256_keypair(priv_hex)
            self.state["ticketGuardPrivateKey"] = priv_hex
            self.state["ticketGuardPublicKey"] = pub_b64
        return str(priv_hex), str(pub_b64)

    def _capture_ticket_guard_server_data(self, response: WreqResponse) -> None:
        raw_server_data = response.headers.get("tt-ticket-guard-server-data")
        if not raw_server_data:
            return
        try:
            decoded = json.loads(base64.b64decode(raw_server_data).decode("utf-8"))
            tickets = decoded.get("tickets") if isinstance(decoded, dict) else None
            if isinstance(tickets, list) and tickets:
                item = tickets[0]
                if isinstance(item, dict) and item.get("ticket"):
                    self.state["ticketGuardTicket"] = str(item["ticket"])
                    raw_ts_sign = str(item.get("ts_sign") or "")
                    ts_sign_ree = raw_ts_sign
                    if raw_ts_sign.startswith("{"):
                        parsed_ts = json.loads(raw_ts_sign)
                        if isinstance(parsed_ts, dict) and parsed_ts.get("ts_sign_ree"):
                            ts_sign_ree = str(parsed_ts["ts_sign_ree"])
                    self.state["ticketGuardTsSign"] = ts_sign_ree
        except Exception:
            pass

    def _request(self, path: str, fields: Mapping[str, Any], *, method: str = "POST") -> dict[str, Any]:
        clean_path = urlsplit(path).path
        is_passport = clean_path.startswith("/passport/")
        body_fields = dict(fields)
        if is_passport and method != "GET":
            body_fields.setdefault("account_sdk_source", "app")
            body_fields.setdefault("multi_login", "1")
        encoded = urlencode(list(body_fields.items()))
        query_params = dict(self.query_params)
        if is_passport:
            query_params.setdefault("passport-sdk-version", "1")
            if method == "GET":
                query_params.setdefault("account_sdk_source", "app")
                query_params.setdefault("multi_login", "1")
        url = with_common_params(self.base_url + path, query_params)
        headers = dict(self.common_headers)
        headers.setdefault("sdk-version", "2")
        headers.setdefault("x-tt-bypass-dp", "1")
        priv_hex, pub_b64 = self._ensure_ticket_guard_key()
        headers.setdefault("tt-ticket-guard-public-key", pub_b64)
        headers.setdefault("tt-ticket-guard-version", "3")
        headers.setdefault("tt-ticket-guard-iteration-version", "0")
        if self.state.get("sessionToken"):
            headers.setdefault("x-tt-token", str(self.state["sessionToken"]))
            tg_ticket = self.state.get("ticketGuardTicket")
            tg_ts_sign = self.state.get("ticketGuardTsSign", "")
            if tg_ticket:
                ts = int(time.time())
                to_sign = f"ticket={tg_ticket}&path={clean_path}&timestamp={ts}".encode("utf-8")
                req_sign = _p256_sign_base64(priv_hex, to_sign)
                client_data = {
                    "req_content": "ticket,path,timestamp",
                    "timestamp": ts,
                    "ts_sign": tg_ts_sign,
                    "req_sign": req_sign,
                }
                headers.setdefault(
                    "tt-ticket-guard-client-data",
                    base64.b64encode(json.dumps(client_data, separators=(",", ":")).encode("utf-8")).decode("ascii"),
                )
        if is_passport:
            headers.setdefault("passport-sdk-version", "1")
            headers.setdefault("passport-sdk-settings", "x-tt-token")
            headers.setdefault("passport-sdk-sign", "x-tt-token")
            headers.setdefault("x-vc-bdturing-sdk-version", "2.4.4.i18n")
            cookies = self.session.get_cookies(url)
            csrf = cookies.get("passport_csrf_token") or cookies.get("passport_csrf_token_default")
            if csrf:
                headers.setdefault("x-tt-passport-csrf-token", csrf)
        if method == "GET":
            response = self.session.get(with_common_params(url, body_fields), headers=headers)
        else:
            response = self.session.post(
                url,
                headers={**headers, "content-type": "application/x-www-form-urlencoded; charset=UTF-8"},
                body=encoded.encode(),
            )
        self._last_response = response
        self._capture_ticket_guard_server_data(response)
        if self._token and "sessionToken" in self.state:
            self.state["sessionToken"] = self._token
        return self._decode(response)
    @property
    def _token(self) -> str | None:
        return getattr(self, "_last_response").headers.get("x-tt-token")

    @staticmethod
    def _data(result: Mapping[str, Any]) -> dict[str, Any]:
        data = result.get("data", {})
        return data if isinstance(data, dict) else {}

    def start_email(self, email: str, code_type: int, *, password: str | None = None) -> dict[str, Any]:
        check = self._request("/passport/user/check_email_registered", {"email": mix_encode(email), "mix_mode": "1"})
        data = self._data(check)
        if data.get("is_registered", 0):
            raise SignupError("email is already registered", code="already_registered", data=data)
        sent = self._request("/passport/email/send_code/", {
            "email": mix_encode(email),
            "type": mix_encode(str(code_type)),
            **({"password": mix_encode(password)} if password is not None else {}),
            "mix_mode": "1",
        })
        sent_data = self._data(sent)
        if sent_data.get("has_account"):
            raise SignupError("email already has an account", code="already_registered", data=sent_data)
        self.state.update({
            "status": "needs_otp",
            "nextAction": "submit_otp",
            "method": "email",
            "email": email,
            "codeType": code_type,
            "hasAccount": sent_data.get("has_account"),
        })
        if password is not None:
            self.state["password"] = password
        return self.public_state()

    def start_mobile(
        self,
        mobile: str,
        code_type: int,
        *,
        auto_read: int = 0,
        check_register: int = 0,
        tickets: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        sent = self._request("/passport/mobile/send_code/v1/", {
            "mobile": mix_encode(mobile),
            "type": mix_encode(str(code_type)),
            "unbind_exist": mix_encode("0"),
            "mix_mode": "1",
            "check_register": str(check_register),
            "is6Digits": "1",
            "auto_read": str(auto_read),
            **dict(tickets or {}),
        })
        data = self._data(sent)
        if data.get("has_account"):
            raise SignupError("mobile already has an account", code="already_registered", data=data)
        self.state.update({
            "status": "needs_otp",
            "nextAction": "submit_otp",
            "method": "mobile",
            "mobile": mobile,
            "codeType": code_type,
            "hasAccount": data.get("has_account"),
            "retryTime": data.get("retry_time", 30),
            **({"mobileTicket": data["mobile_ticket"]} if data.get("mobile_ticket") else {}),
        })
        return self.public_state()

    def submit_otp(self, code: str) -> dict[str, Any]:
        if self.state.get("status") != "needs_otp":
            raise SignupError("OTP is not expected in this state", next_action=self.state.get("nextAction", "failed"))
        if self.state.get("method") == "email":
            result = self._request("/passport/email/check_code/", {
                "email": mix_encode(self.state["email"]),
                "code": mix_encode(code),
                "type": mix_encode(str(self.state["codeType"])),
                "mix_mode": "1",
                "fixed_mix_mode": "1",
            })
        elif self.state.get("method") == "mobile":
            result = self._request("/passport/mobile/check_code/", {
                "mobile": mix_encode(self.state["mobile"]),
                "code": mix_encode(code),
                "type": mix_encode(str(self.state["codeType"])),
                "mix_mode": "1",
                "fixed_mix_mode": "1",
            })
        else:
            raise SignupError("signup method is not initialized")
        ticket = self._data(result).get("ticket")
        if not ticket:
            raise SignupError("check_code response is missing data.ticket", data=result)
        self.state.update({
            "status": "verified",
            "nextAction": "complete",
            "ticket": ticket,
            "otp": code,
        })
        return self.public_state()

    def _complete_result(self, result: Mapping[str, Any]) -> None:
        token = self._token
        if not token:
            raise SignupError("registration response is missing x-tt-token", data=result)
        if not isinstance(result.get("data"), dict) or not result["data"]:
            raise SignupError("registration response is missing user data", data=result)
        self.state.update({
            "status": "completed",
            "nextAction": "completed",
            "result": result,
            "sessionToken": token,
        })

    def complete_email(
        self,
        *,
        password: str | None = None,
        recaptcha_token: str | None = None,
    ) -> dict[str, Any]:
        if self.state.get("status") != "verified" or self.state.get("method") != "email":
            raise SignupError("email OTP verification is required first")
        password = password or self.state.get("password")
        if not password:
            raise SignupError("password is required", next_action="needs_password")
        result = self._request("/passport/email/register/v2/", {
            "email": mix_encode(self.state["email"]),
            **({"code": mix_encode(self.state["otp"])} if self.state.get("otp") else {}),
            "password": mix_encode(password),
            **({"recaptcha_token": recaptcha_token} if recaptcha_token else {}),
            "mix_mode": "1",
            "fixed_mix_mode": "1",
        })
        self._complete_result(result)
        return self.public_state()

    def complete_mobile(
        self,
        *,
        captcha: str | None = None,
        not_login_ticket: str | None = None,
    ) -> dict[str, Any]:
        if self.state.get("status") != "verified" or self.state.get("method") != "mobile":
            raise SignupError("mobile OTP verification is required first")
        result = self._request("/passport/mobile/sms_login/", {
            "mobile": mix_encode(self.state["mobile"]),
            **({"captcha": captcha} if captcha else {}),
            "code": mix_encode(self.state["otp"]),
            "mix_mode": "1",
            "not_login_ticket": not_login_ticket or self.state["ticket"],
        })
        sms_code_key = self._data(result).get("sms_code_key")
        if sms_code_key:
            result = self._request("/passport/mobile/sms_login_continue/", {
                "mobile": mix_encode(self.state["mobile"]),
                "sms_code_key": mix_encode(str(sms_code_key)),
                "mix_mode": "1",
            })
        self._complete_result(result)
        return self.public_state()

    def submit_birthday(
        self,
        birthday: str,
        *,
        update_birthdate_type: int,
        session_register_type: int,
        is_guest: bool = True,
        submit_type: int | None = None,
    ) -> dict[str, Any]:
        result = self._request("/tiktok/v1/calculate/age/", {
            "birthday": birthday,
            "update_birthdate_type": str(update_birthdate_type),
            "session_register_type": str(session_register_type),
            "is_guest": "true" if is_guest else "false",
            **({"submit_type": str(submit_type)} if submit_type is not None else {}),
        }, method="GET")
        data = self._data(result)
        self.state.update({
            "age": data.get("age"),
            "appealUrl": data.get("appeal_url"),
            "verificationReason": data.get("verification_reason"),
        })
        return self.public_state()

    def complete_email_verify_login(self) -> dict[str, Any]:
        if self.state.get("status") != "verified" or self.state.get("method") != "email":
            raise SignupError("email OTP verification is required first")
        result = self._request("/passport/email/register_verify_login/", {
            "email": mix_encode(self.state["email"]),
            "type": mix_encode(str(self.state["codeType"])),
            **({"code": mix_encode(self.state["otp"])} if self.state.get("otp") else {}),
            "mix_mode": "1",
            "fixed_mix_mode": "1",
        })
        self._complete_result(result)
        return self.public_state()

    def complete_mobile_login_only(
        self,
        code: str | None = None,
        *,
        birthday: str | None = None,
        carrier_region: str | None = None,
        verify_reused_mobile: bool = True,
        captcha: str | None = None,
    ) -> dict[str, Any]:
        otp = code or self.state.get("otp")
        if self.state.get("method") != "mobile" or self.state.get("status") not in {"needs_otp", "verified"} or not otp:
            raise SignupError("mobile OTP verification is required first")
        self.state["otp"] = otp
        result = self._request("/passport/mobile/sms_login_only/", {
            "mobile": mix_encode(self.state["mobile"]),
            **({"captcha": captcha} if captcha else {}),
            "code": mix_encode(str(otp)),
            "mix_mode": "1",
            "enable_account_selection": "1",
            "scene": "0",
            **({"verify_reused_mobile": "true"} if verify_reused_mobile else {}),
        })
        sms_code_key = self._data(result).get("sms_code_key")
        if sms_code_key:
            self.state["smsCodeKey"] = str(sms_code_key)
            result = self._request("/passport/mobile/sms_login_continue/", {
                "mobile": mix_encode(self.state["mobile"]),
                "sms_code_key": mix_encode(str(sms_code_key)),
                "mix_mode": "1",
                **({"birthday": birthday} if birthday else {}),
                **({"carrier_region": carrier_region} if carrier_region else {}),
            })
        self._complete_result(result)
        return self.public_state()

    def verify_age(
        self,
        birthday: str,
        *,
        update_birthdate_type: int,
        session_registered: int,
        birthday_confidence: int,
        is_guest: bool = True,
        submit_type: int | None = None,
        age_range_source: str | None = None,
        third_party_lower_bound: int | None = None,
        third_party_upper_bound: int | None = None,
    ) -> dict[str, Any]:
        query = {
            **({"age_range_source": age_range_source} if age_range_source else {}),
            **({"third_party_lower_bound": str(third_party_lower_bound)} if third_party_lower_bound is not None else {}),
            **({"third_party_upper_bound": str(third_party_upper_bound)} if third_party_upper_bound is not None else {}),
        }
        path = "/aweme/v3/verification/age/"
        if query:
            path += "?" + urlencode(query)
        result = self._request(path, {
            "birthday": birthday,
            "update_birthdate_type": str(update_birthdate_type),
            "session_registered": str(session_registered),
            "is_guest": "true" if is_guest else "false",
            "birthday_confidence": str(birthday_confidence),
            **({"submit_type": str(submit_type)} if submit_type is not None else {}),
        })
        data = self._data(result)
        self.state.update({
            "isPrompt": data.get("is_prompt", False),
            "registerAgeGatePostAction": data.get("register_age_gate_post_action"),
            "ageGatePostAction": data.get("age_gate_post_action"),
            "isMixedAge": data.get("is_mixed_age"),
            "supplementAction": data.get("supplement_action"),
            "needScreenTimeReminder": data.get("need_screen_time_reminder"),
        })
        return self.public_state()

    def set_password(self, password: str, *, rules_version: str = "v2") -> dict[str, Any]:
        self.state["result"] = self._request("/passport/password/set/", {
            "password": mix_encode(password),
            "mix_mode": "1",
            "rules_version": rules_version,
        })
        self.state["nextAction"] = "completed"
        self.state["status"] = "completed"
        return self.public_state()

    def register_username(self, username: str, password: str) -> dict[str, Any]:
        result = self._request("/passport/username/register/", {
            "username": mix_encode(username),
            "password": mix_encode(password),
            "mix_mode": "1",
        })
        self._complete_result(result)
        return self.public_state()

    def check_login_name(self, login_name: str) -> dict[str, Any]:
        result = self._request("/passport/login_name/check/", {
            "login_name": login_name,
        })
        data = self._data(result)
        recommended = data.get("recommended_login_names")
        self.state.update({
            "loginName": data.get("login_name", login_name),
            "loginNameAvailable": True,
            **(
                {"recommendedLoginNames": list(recommended)}
                if isinstance(recommended, list)
                else {}
            ),
        })
        return self.public_state()

    def register_login_name(
        self,
        login_name: str,
        *,
        is_from_nickname: bool = False,
        aid: int | str | None = None,
    ) -> dict[str, Any]:
        resolved_aid = aid if aid is not None else self.query_params.get("aid", "1233")
        result = self._request("/passport/login_name/register/", {
            "aid": str(resolved_aid),
            "login_name": login_name,
            "is_from_nickname": "true" if is_from_nickname else "false",
        })
        data = self._data(result)
        final_name = str(data.get("login_name") or login_name)
        self.state.update({
            "loginName": final_name,
            "uniqueId": final_name,
        })
        return self.public_state()

    def update_login_name(self, login_name: str) -> dict[str, Any]:
        result = self._request("/passport/login_name/update/", {
            "login_name": login_name,
        })
        data = self._data(result)
        final_name = str(data.get("login_name") or login_name)
        self.state.update({
            "loginName": final_name,
            "uniqueId": final_name,
        })
        return self.public_state()

    def commit_user_profile(
        self,
        *,
        nickname: str | None = None,
        signature: str | None = None,
        avatar_uri: str | None = None,
        unique_id: str | None = None,
        extra_fields: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        fields: dict[str, Any] = dict(extra_fields or {})
        if nickname is not None:
            fields["nickname"] = nickname
        if signature is not None:
            fields["signature"] = signature
        if avatar_uri is not None:
            fields["avatar_uri"] = avatar_uri
        if unique_id is not None:
            fields["unique_id"] = unique_id
        if not fields:
            raise SignupError("at least one profile field is required")
        result = self._request("/aweme/v1/commit/user/", fields)
        user = result.get("user") if isinstance(result.get("user"), dict) else {}
        self.state.update({
            **(
                {"nickname": user.get("nickname", nickname)}
                if nickname is not None or "nickname" in user
                else {}
            ),
            **(
                {"signature": user.get("signature", signature)}
                if signature is not None or "signature" in user
                else {}
            ),
            **(
                {"avatarUri": avatar_uri}
                if avatar_uri is not None
                else {}
            ),
            **(
                {"uniqueId": user.get("unique_id", unique_id)}
                if unique_id is not None or "unique_id" in user
                else {}
            ),
        })
        return self.public_state()

    def token_beat(self, *, scene: str = "boot", first_beat: bool = True) -> dict[str, Any]:
        self._request("/passport/token/beat/v2/", {
            "scene": scene,
            "first_beat": "true" if first_beat else "false",
        }, method="GET")
        self.state["tokenBeatScene"] = scene
        return self.public_state()

    def get_account_info(
        self,
        *,
        scene: str = "login",
        device_migrate_time: int = 0,
        get_info_type: int | None = 1,
    ) -> dict[str, Any]:
        fields: dict[str, Any] = {
            "scene": scene,
            "device_migrate_time": str(device_migrate_time),
        }
        if get_info_type is not None:
            fields["get_info_type"] = str(get_info_type)
        result = self._request("/passport/account/info/v2/", fields)
        data = self._data(result)
        uid = data.get("user_id_str") or (str(data["user_id"]) if data.get("user_id") else None)
        screen_name = data.get("screen_name") or data.get("username")
        self.state.update({
            **({"accountUserId": uid} if uid else {}),
            **({"screenName": str(screen_name)} if screen_name else {}),
        })
        return self.public_state()

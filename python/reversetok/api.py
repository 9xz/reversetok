"""Authenticated HTTP API for resumable signup attempts."""
from __future__ import annotations

import base64
import binascii
import hmac
import json
import os
import threading
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from wreq import Proxy

from .crypto import VERSION
from .registration import DEFAULT_REGISTRATION_URL, DeviceRegistrationClient, RegistrationResponseError
from .session_state import restore_cookie_jar
from .signer import MetaSecSigner
from .signup import SignupClient, SignupError
from .store import (
    AttemptConflict,
    AttemptExpired,
    AttemptNotFound,
    AttemptRecord,
    AttemptStore,
)
from .wreq_client import WreqSession


@dataclass(frozen=True)
class ApiConfig:
    api_key: str
    persona: dict
    base_url: str = "https://api16-normal-c-alisg.tiktokv.com"
    proxy: str | None = None
    attempt_ttl_seconds: int = 3600
    rate_limit_per_minute: int = 120
    max_body_bytes: int = 1_000_000
    registration_endpoint: str = DEFAULT_REGISTRATION_URL
    registration_overrides: dict[str, Any] = field(default_factory=dict)
    registration_query_params: dict[str, Any] = field(default_factory=dict)
    common_headers: dict[str, str] = field(default_factory=dict)
    signup_common_headers: dict[str, str] = field(default_factory=dict)
    signup_query_params: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.api_key:
            raise ValueError("api_key must not be empty")
        if not isinstance(self.persona, dict):
            raise TypeError("persona must be a dict")
        if not self.base_url:
            raise ValueError("base_url must not be empty")
        if self.attempt_ttl_seconds <= 0:
            raise ValueError("attempt_ttl_seconds must be positive")
        if self.rate_limit_per_minute <= 0:
            raise ValueError("rate_limit_per_minute must be positive")
        if self.max_body_bytes <= 0:
            raise ValueError("max_body_bytes must be positive")
        if not self.registration_endpoint:
            raise ValueError("registration_endpoint must not be empty")


class _CreateSignup(BaseModel):
    method: Literal["email", "mobile"]
    code_type: int
    email: str | None = Field(default=None, min_length=1)
    mobile: str | None = Field(default=None, min_length=1)
    password: str | None = None


class _Otp(BaseModel):
    code: str = Field(min_length=1)


class _Password(BaseModel):
    password: str
    recaptcha_token: str | None = None


class _Challenge(BaseModel):
    captcha: str | None = None
    recaptcha_token: str | None = None
    not_login_ticket: str | None = None


class _Birthday(BaseModel):
    birthday: str
    update_birthdate_type: int
    session_register_type: int
    is_guest: bool = True
    submit_type: int | None = None


class _AgeVerification(BaseModel):
    birthday: str
    update_birthdate_type: int
    session_registered: int
    birthday_confidence: int
    is_guest: bool = True
    submit_type: int | None = None
    age_range_source: str | None = None
    third_party_lower_bound: int | None = None
    third_party_upper_bound: int | None = None


class _Username(BaseModel):
    username: str
    password: str


class _PasswordSet(BaseModel):
    password: str


class _LoginOnly(BaseModel):
    code: str | None = None
    birthday: str | None = None
    carrier_region: str | None = None
    captcha: str | None = None


class _LoginName(BaseModel):
    login_name: str = Field(min_length=1)


class _RegisterLoginName(BaseModel):
    login_name: str = Field(min_length=1)
    is_from_nickname: bool = False
    aid: int | str | None = None


class _CommitProfile(BaseModel):
    nickname: str | None = None
    signature: str | None = None
    avatar_uri: str | None = None
    unique_id: str | None = None
    extra_fields: dict[str, Any] = Field(default_factory=dict)


class _TokenBeat(BaseModel):
    scene: str = "boot"
    first_beat: bool = True


class _AccountInfo(BaseModel):
    scene: str = "login"
    device_migrate_time: int = 0
    get_info_type: int | None = 1

class _RegistrationRequest(BaseModel):
    overrides: dict[str, Any] = Field(default_factory=dict)
    common_headers: dict[str, str] = Field(default_factory=dict)
    replay: dict[str, Any] | None = None


class _SignRequest(BaseModel):
    url: str
    method: str = "GET"
    persona: dict[str, Any] | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    body_base64: str = ""
    replay: dict[str, Any] | None = None


class _RateLimiter:
    def __init__(self, limit: int):
        self._limit = limit
        self._lock = threading.Lock()
        self._requests: deque[float] = deque()

    def allow(self) -> bool:
        now = time.monotonic()
        with self._lock:
            cutoff = now - 60.0
            while self._requests and self._requests[0] <= cutoff:
                self._requests.popleft()
            if len(self._requests) >= self._limit:
                return False
            self._requests.append(now)
            return True


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _json_object_env(name: str) -> dict[str, Any]:
    value = os.environ.get(name)
    if not value:
        return {}
    try:
        result = json.loads(value)
    except json.JSONDecodeError as error:
        raise ValueError(f"{name} must be valid JSON") from error
    if not isinstance(result, dict):
        raise ValueError(f"{name} must contain a JSON object")
    return result


def create_app(store: AttemptStore, config: ApiConfig) -> FastAPI:
    limiter = _RateLimiter(config.rate_limit_per_minute)

    async def authorize(authorization: str | None = Header(default=None)) -> None:
        expected = f"Bearer {config.api_key}".encode("utf-8")
        supplied = (authorization or "").encode("utf-8")
        if not hmac.compare_digest(supplied, expected):
            raise HTTPException(
                status_code=401,
                detail="invalid bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        store.close()
    app = FastAPI(
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        dependencies=[Depends(authorize)],
    )
    app.state.attempt_store = store
    app.state.api_config = config

    def error_response(
        status_code: int, detail: str, *, headers: dict[str, str] | None = None
    ) -> JSONResponse:
        return JSONResponse(status_code=status_code, content={"detail": detail}, headers=headers)

    @app.exception_handler(AttemptNotFound)
    async def attempt_not_found(_request: Request, _exc: AttemptNotFound) -> JSONResponse:
        return error_response(404, "signup not found")

    @app.exception_handler(AttemptConflict)
    async def attempt_conflict(_request: Request, _exc: AttemptConflict) -> JSONResponse:
        return error_response(409, "signup state conflict")

    @app.exception_handler(AttemptExpired)
    async def attempt_expired(_request: Request, _exc: AttemptExpired) -> JSONResponse:
        return error_response(410, "signup expired")

    @app.exception_handler(RequestValidationError)
    async def request_invalid(_request: Request, _exc: RequestValidationError) -> JSONResponse:
        return error_response(400, "invalid request")

    @app.exception_handler(ValueError)
    async def value_invalid(_request: Request, _exc: ValueError) -> JSONResponse:
        return error_response(400, "invalid request")

    @app.exception_handler(RegistrationResponseError)
    async def registration_failed(_request: Request, _exc: RegistrationResponseError) -> JSONResponse:
        return error_response(502, "device registration failed")

    @app.exception_handler(SignupError)
    async def signup_failed(_request: Request, exc: SignupError) -> JSONResponse:
        content: dict[str, Any] = {
            "detail": "signup flow failed",
            "next_action": exc.next_action if isinstance(exc.next_action, str) else "failed",
        }
        if isinstance(exc.code, (str, int)) and not isinstance(exc.code, bool):
            content["code"] = exc.code
        return JSONResponse(status_code=422, content=content)

    @app.middleware("http")
    async def protect_response(request: Request, call_next: Any) -> Response:
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                body_size = int(content_length)
            except ValueError:
                return JSONResponse(status_code=400, content={"detail": "invalid content length"}, headers={"Cache-Control": "no-store"})
            if body_size < 0:
                return JSONResponse(status_code=400, content={"detail": "invalid content length"}, headers={"Cache-Control": "no-store"})
            if body_size > config.max_body_bytes:
                return JSONResponse(status_code=413, content={"detail": "request body too large"}, headers={"Cache-Control": "no-store"})
        if not limiter.allow():
            return JSONResponse(status_code=429, content={"detail": "rate limit exceeded"}, headers={"Cache-Control": "no-store", "Retry-After": "60"})
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        return response

    def public_response(record: AttemptRecord) -> dict[str, Any]:
        public = dict(record.payload.get("public") or {})
        if record.status in {"cancelled", "expired", "failed"}:
            public["status"] = record.status
            public["nextAction"] = record.status
        return {
            **public,
            "id": record.id,
            "created_at": record.created_at,
            "updated_at": record.updated_at,
            "expires_at": record.expires_at,
        }

    def registration_response(record: AttemptRecord) -> dict[str, Any]:
        return {
            **record.payload["identity"],
            "id": record.id,
            "created_at": record.created_at,
            "updated_at": record.updated_at,
            "expires_at": record.expires_at,
        }

    def new_session() -> WreqSession:
        options: dict[str, Any] = {}
        if config.proxy:
            options["proxies"] = [Proxy.all(config.proxy)]
        return WreqSession(config.persona, **options)

    def start_signup(body: _CreateSignup) -> tuple[dict[str, Any], dict[str, Any]]:
        with new_session() as session:
            client = SignupClient(
                session,
                base_url=config.base_url,
                common_headers=config.signup_common_headers,
                query_params=config.signup_query_params,
            )
            if body.method == "email":
                public = client.start_email(
                    body.email or "", body.code_type, password=body.password
                )
            else:
                public = client.start_mobile(body.mobile or "", body.code_type)
            snapshot = client.snapshot()
        return {"snapshot": snapshot, "public": public}, public

    def resume_signup(
        record: AttemptRecord, operation: Any
    ) -> tuple[AttemptRecord, dict[str, Any]]:
        if record.status in {"cancelled", "expired", "failed"}:
            raise AttemptConflict(record.id)
        snapshot = record.payload["snapshot"]
        with new_session() as session:
            restore_cookie_jar(session.cookie_jar, snapshot["cookies"])
            client = SignupClient(
                session,
                base_url=config.base_url,
                state=snapshot["state"],
                common_headers=config.signup_common_headers,
                query_params=config.signup_query_params,
            )
            public = operation(client)
            updated_snapshot = client.snapshot()
        payload = {"snapshot": updated_snapshot, "public": public}
        updated = store.update(
            record.id,
            public.get("status", record.status),
            payload,
            expected_statuses={record.status},
        )
        return updated, public

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "native_version": VERSION}

    @app.post("/v1/signups")
    def create_signup(
        body: _CreateSignup,
        idempotency_key: str = Header(
            ..., alias="X-Idempotency-Key", min_length=1, max_length=512
        ),
    ) -> dict[str, Any]:
        if body.method == "email" and not body.email:
            raise HTTPException(status_code=400, detail="email is required")
        if body.method == "mobile" and not body.mobile:
            raise HTTPException(status_code=400, detail="mobile is required")

        reservation = uuid.uuid4().hex
        record = store.create(
            "signup",
            {
                "reservation": reservation,
                "public": {"status": "pending", "nextAction": "start"},
            },
            idempotency_key,
            config.attempt_ttl_seconds,
        )
        if record.payload.get("reservation") != reservation:
            record = store.get(record.id)
            if record.status == "pending" and record.payload.get("snapshot") is None:
                raise AttemptConflict(record.id)
            return public_response(record)

        try:
            payload, public = start_signup(body)
        except Exception:
            try:
                store.delete(record.id)
            except AttemptNotFound:
                pass
            raise
        record = store.update(
            record.id,
            public.get("status", "pending"),
            payload,
            expected_statuses={"pending"},
        )
        return public_response(record)

    @app.get("/v1/signups/{attempt_id}")
    def get_signup(attempt_id: str) -> dict[str, Any]:
        return public_response(store.get(attempt_id))

    @app.post("/v1/signups/{attempt_id}/otp")
    def submit_otp(attempt_id: str, body: _Otp) -> dict[str, Any]:
        record = store.get(attempt_id)
        updated, _ = resume_signup(record, lambda client: client.submit_otp(body.code))
        return public_response(updated)

    @app.post("/v1/signups/{attempt_id}/password")
    def complete_password(attempt_id: str, body: _Password) -> dict[str, Any]:
        record = store.get(attempt_id)
        updated, _ = resume_signup(
            record,
            lambda client: client.complete_email(
                password=body.password, recaptcha_token=body.recaptcha_token
            ),
        )
        return public_response(updated)

    @app.post("/v1/signups/{attempt_id}/email-verify-login")
    def complete_email_verify_login(attempt_id: str) -> dict[str, Any]:
        record = store.get(attempt_id)
        updated, _ = resume_signup(record, lambda client: client.complete_email_verify_login())
        return public_response(updated)

    @app.post("/v1/signups/{attempt_id}/mobile-login-only")
    def complete_mobile_login_only(attempt_id: str, body: _LoginOnly) -> dict[str, Any]:
        record = store.get(attempt_id)
        updated, _ = resume_signup(
            record,
            lambda client: client.complete_mobile_login_only(
                body.code,
                birthday=body.birthday,
                carrier_region=body.carrier_region,
                captcha=body.captcha,
            ),
        )
        return public_response(updated)

    @app.post("/v1/signups/{attempt_id}/challenge")
    def complete_challenge(attempt_id: str, body: _Challenge) -> dict[str, Any]:
        record = store.get(attempt_id)
        method = record.payload["snapshot"]["state"].get("method")
        if method == "mobile":
            operation = lambda client: client.complete_mobile(
                captcha=body.captcha, not_login_ticket=body.not_login_ticket
            )
        else:
            operation = lambda client: client.complete_email(
                recaptcha_token=body.recaptcha_token
            )
        updated, _ = resume_signup(record, operation)
        return public_response(updated)

    @app.post("/v1/signups/{attempt_id}/birthday")
    def submit_birthday(attempt_id: str, body: _Birthday) -> dict[str, Any]:
        record = store.get(attempt_id)
        updated, _ = resume_signup(
            record,
            lambda client: client.submit_birthday(
                body.birthday,
                update_birthdate_type=body.update_birthdate_type,
                session_register_type=body.session_register_type,
                is_guest=body.is_guest,
                submit_type=body.submit_type,
            ),
        )
        return public_response(updated)

    @app.post("/v1/signups/{attempt_id}/age-verification")
    def verify_age(attempt_id: str, body: _AgeVerification) -> dict[str, Any]:
        record = store.get(attempt_id)
        updated, _ = resume_signup(
            record,
            lambda client: client.verify_age(
                body.birthday,
                update_birthdate_type=body.update_birthdate_type,
                session_registered=body.session_registered,
                birthday_confidence=body.birthday_confidence,
                is_guest=body.is_guest,
                submit_type=body.submit_type,
                age_range_source=body.age_range_source,
                third_party_lower_bound=body.third_party_lower_bound,
                third_party_upper_bound=body.third_party_upper_bound,
            ),
        )
        return public_response(updated)

    @app.post("/v1/signups/{attempt_id}/username")
    def register_username(attempt_id: str, body: _Username) -> dict[str, Any]:
        record = store.get(attempt_id)
        updated, _ = resume_signup(
            record,
            lambda client: client.register_username(body.username, body.password),
        )
        return public_response(updated)

    @app.post("/v1/signups/{attempt_id}/password-set")
    def set_password(attempt_id: str, body: _PasswordSet) -> dict[str, Any]:
        record = store.get(attempt_id)
        updated, _ = resume_signup(
            record, lambda client: client.set_password(body.password)
        )
        return public_response(updated)


    @app.post("/v1/signups/{attempt_id}/login-name/check")
    def check_login_name(attempt_id: str, body: _LoginName) -> dict[str, Any]:
        record = store.get(attempt_id)
        updated, _ = resume_signup(
            record, lambda client: client.check_login_name(body.login_name)
        )
        return public_response(updated)

    @app.post("/v1/signups/{attempt_id}/login-name/register")
    def register_login_name(
        attempt_id: str, body: _RegisterLoginName
    ) -> dict[str, Any]:
        record = store.get(attempt_id)
        updated, _ = resume_signup(
            record,
            lambda client: client.register_login_name(
                body.login_name,
                is_from_nickname=body.is_from_nickname,
                aid=body.aid,
            ),
        )
        return public_response(updated)

    @app.post("/v1/signups/{attempt_id}/login-name/update")
    def update_login_name(attempt_id: str, body: _LoginName) -> dict[str, Any]:
        record = store.get(attempt_id)
        updated, _ = resume_signup(
            record, lambda client: client.update_login_name(body.login_name)
        )
        return public_response(updated)

    @app.post("/v1/signups/{attempt_id}/profile")
    def commit_user_profile(attempt_id: str, body: _CommitProfile) -> dict[str, Any]:
        record = store.get(attempt_id)
        updated, _ = resume_signup(
            record,
            lambda client: client.commit_user_profile(
                nickname=body.nickname,
                signature=body.signature,
                avatar_uri=body.avatar_uri,
                unique_id=body.unique_id,
                extra_fields=body.extra_fields,
            ),
        )
        return public_response(updated)

    @app.post("/v1/signups/{attempt_id}/token-beat")
    def token_beat(
        attempt_id: str, body: _TokenBeat = _TokenBeat()
    ) -> dict[str, Any]:
        record = store.get(attempt_id)
        updated, _ = resume_signup(
            record,
            lambda client: client.token_beat(
                scene=body.scene, first_beat=body.first_beat
            ),
        )
        return public_response(updated)

    @app.post("/v1/signups/{attempt_id}/account-info")
    def get_account_info(
        attempt_id: str, body: _AccountInfo = _AccountInfo()
    ) -> dict[str, Any]:
        record = store.get(attempt_id)
        updated, _ = resume_signup(
            record,
            lambda client: client.get_account_info(
                scene=body.scene,
                device_migrate_time=body.device_migrate_time,
                get_info_type=body.get_info_type,
            ),
        )
        return public_response(updated)
    @app.post("/v1/signups/{attempt_id}/cancel")
    def cancel_signup(attempt_id: str) -> dict[str, Any]:
        return public_response(store.cancel(attempt_id))

    @app.delete("/v1/signups/{attempt_id}", status_code=204)
    def delete_signup(attempt_id: str) -> Response:
        store.delete(attempt_id)
        return Response(status_code=204)

    @app.post("/v1/sign")
    def sign_offline(body: _SignRequest) -> dict[str, Any]:
        body_bytes = base64.b64decode(body.body_base64, validate=True)
        result = MetaSecSigner(body.persona or config.persona).sign_request(
            body.url,
            method=body.method,
            headers=body.headers,
            body=body_bytes,
            **dict(body.replay or {}),
        )
        return {
            "headers": result["headers"],
            "method": result["method"],
            "url": result["url"],
            "bodyBase64": result["bodyBase64"],
        }

    @app.post("/v1/device-registrations")
    def register_device(
        body: _RegistrationRequest,
        idempotency_key: str = Header(
            ..., alias="X-Idempotency-Key", min_length=1, max_length=512
        ),
    ) -> dict[str, Any]:
        reservation = uuid.uuid4().hex
        record = store.create(
            "device-registration",
            {
                "reservation": reservation,
                "public": {"status": "pending", "nextAction": "register"},
            },
            idempotency_key,
            config.attempt_ttl_seconds,
        )
        if record.payload.get("reservation") != reservation:
            if "identity" not in record.payload:
                raise AttemptConflict(record.id)
            return registration_response(record)
        try:
            with new_session() as session:
                client = DeviceRegistrationClient(
                    session,
                    config.persona,
                    common_headers={**config.common_headers, **body.common_headers},
                    overrides={**config.registration_overrides, **body.overrides},
                    query_params=config.registration_query_params,
                    endpoint=config.registration_endpoint,
                )
                identity = client.register(replay=body.replay)
        except Exception:
            try:
                store.delete(record.id)
            except AttemptNotFound:
                pass
            raise
        record = store.update(
            record.id,
            "completed",
            {
                "identity": identity,
                "public": {"status": "completed", "nextAction": "completed"},
            },
            expected_statuses={"pending"},
        )
        return registration_response(record)
    return app


def create_app_from_env() -> FastAPI:
    api_key = _required_env("REVERSETOK_API_KEY")
    encoded_key = _required_env("REVERSETOK_STATE_KEY")
    try:
        state_key = base64.b64decode(encoded_key, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("REVERSETOK_STATE_KEY must be valid base64") from error
    if len(state_key) != 32:
        raise ValueError("REVERSETOK_STATE_KEY must decode to exactly 32 bytes")

    try:
        persona = json.loads(_required_env("REVERSETOK_PERSONA_JSON"))
    except json.JSONDecodeError as error:
        raise ValueError("REVERSETOK_PERSONA_JSON must be valid JSON") from error
    if not isinstance(persona, dict):
        raise ValueError("REVERSETOK_PERSONA_JSON must contain a JSON object")

    state_path = Path(
        os.environ.get("REVERSETOK_STATE_PATH") or "~/.reversetok/attempts.sqlite"
    ).expanduser()
    config = ApiConfig(
        api_key=api_key,
        persona=persona,
        base_url=os.environ.get("REVERSETOK_API_BASE_URL")
        or ApiConfig.base_url,
        proxy=os.environ.get("REVERSETOK_PROXY") or None,
        registration_endpoint=os.environ.get("REVERSETOK_REGISTRATION_ENDPOINT") or DEFAULT_REGISTRATION_URL,
        registration_overrides=_json_object_env("REVERSETOK_REGISTRATION_OVERRIDES_JSON"),
        registration_query_params=_json_object_env("REVERSETOK_REGISTRATION_QUERY_JSON"),
        common_headers=_json_object_env("REVERSETOK_COMMON_HEADERS_JSON"),
        signup_common_headers=_json_object_env("REVERSETOK_SIGNUP_HEADERS_JSON"),
        signup_query_params=_json_object_env("REVERSETOK_SIGNUP_QUERY_JSON"),
    )
    return create_app(AttemptStore(state_path, state_key), config)

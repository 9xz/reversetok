"""Encrypted durable storage for protocol attempts."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Collection, Iterator

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True)
class AttemptRecord:
    id: str
    kind: str
    status: str
    payload: dict[str, Any]
    created_at: int
    updated_at: int
    expires_at: int


class AttemptNotFound(Exception):
    """Raised when an attempt does not exist."""


class AttemptConflict(Exception):
    """Raised when an attempt is not in an expected status."""


class AttemptExpired(Exception):
    """Raised when an expired attempt is read or changed."""


class AttemptStore:
    """Store JSON attempt payloads encrypted with AES-256-GCM."""

    def __init__(self, path: Path, key: bytes):
        if not isinstance(key, bytes):
            raise TypeError("key must be bytes")
        if len(key) != 32:
            raise ValueError("key must be exactly 32 bytes")

        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._aesgcm = AESGCM(key)
        self._lock = threading.Lock()
        self._closed = False

        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS attempts (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    ciphertext BLOB NOT NULL,
                    nonce BLOB NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS attempts_kind_idempotency_key
                    ON attempts (kind, idempotency_key);
                """
            )

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._closed:
                raise RuntimeError("attempt store is closed")

        connection = sqlite3.connect(self._path, timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
        finally:
            connection.close()

    @staticmethod
    def _now() -> int:
        return int(time.time())

    @staticmethod
    def _aad(attempt_id: str, kind: str) -> bytes:
        return json.dumps([attempt_id, kind], separators=(",", ":")).encode("utf-8")

    def _encrypt(
        self, attempt_id: str, kind: str, payload: dict[str, Any]
    ) -> tuple[bytes, bytes]:
        plaintext = json.dumps(
            payload, separators=(",", ":"), sort_keys=True, allow_nan=False
        ).encode("utf-8")
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(
            nonce, plaintext, self._aad(attempt_id, kind)
        )
        return ciphertext, nonce

    def _record(self, row: sqlite3.Row) -> AttemptRecord:
        plaintext = self._aesgcm.decrypt(
            bytes(row["nonce"]),
            bytes(row["ciphertext"]),
            self._aad(row["id"], row["kind"]),
        )
        return AttemptRecord(
            id=row["id"],
            kind=row["kind"],
            status=row["status"],
            payload=json.loads(plaintext.decode("utf-8")),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            expires_at=row["expires_at"],
        )

    @staticmethod
    def _mark_expired(
        connection: sqlite3.Connection, row: sqlite3.Row, now: int
    ) -> bool:
        if row["expires_at"] > now:
            return False
        if row["status"] != "expired":
            connection.execute(
                "UPDATE attempts SET status = 'expired', updated_at = ? WHERE id = ?",
                (now, row["id"]),
            )
        return True

    def create(
        self,
        kind: str,
        payload: dict[str, Any],
        idempotency_key: str,
        ttl_seconds: int,
    ) -> AttemptRecord:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")

        with self._connection() as connection:
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT * FROM attempts WHERE kind = ? AND idempotency_key = ?",
                    (kind, idempotency_key),
                ).fetchone()
                if existing is not None:
                    return self._record(existing)

                attempt_id = str(uuid.uuid4())
                now = self._now()
                ciphertext, nonce = self._encrypt(attempt_id, kind, payload)
                connection.execute(
                    """
                    INSERT INTO attempts (
                        id, kind, status, ciphertext, nonce, idempotency_key,
                        created_at, updated_at, expires_at
                    ) VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        attempt_id,
                        kind,
                        ciphertext,
                        nonce,
                        idempotency_key,
                        now,
                        now,
                        now + ttl_seconds,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
                ).fetchone()
        return self._record(row)

    def get(self, attempt_id: str) -> AttemptRecord:
        expired = False
        with self._connection() as connection:
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
                ).fetchone()
                if row is None:
                    raise AttemptNotFound(attempt_id)
                expired = self._mark_expired(connection, row, self._now())

        if expired:
            raise AttemptExpired(attempt_id)
        return self._record(row)

    def update(
        self,
        attempt_id: str,
        status: str,
        payload: dict[str, Any],
        expected_statuses: Collection[str] | None = None,
        extend_expiry: int | None = None,
    ) -> AttemptRecord:
        if extend_expiry is not None and extend_expiry <= 0:
            raise ValueError("extend_expiry must be positive")

        expired = False
        with self._connection() as connection:
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
                ).fetchone()
                if row is None:
                    raise AttemptNotFound(attempt_id)

                now = self._now()
                expired = self._mark_expired(connection, row, now)
                if not expired:
                    if (
                        expected_statuses is not None
                        and row["status"] not in expected_statuses
                    ):
                        raise AttemptConflict(attempt_id)

                    ciphertext, nonce = self._encrypt(
                        attempt_id, row["kind"], payload
                    )
                    expires_at = row["expires_at"]
                    if extend_expiry is not None:
                        expires_at += extend_expiry
                    connection.execute(
                        """
                        UPDATE attempts
                        SET status = ?, ciphertext = ?, nonce = ?,
                            updated_at = ?, expires_at = ?
                        WHERE id = ?
                        """,
                        (
                            status,
                            ciphertext,
                            nonce,
                            now,
                            expires_at,
                            attempt_id,
                        ),
                    )
                    row = connection.execute(
                        "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
                    ).fetchone()

        if expired:
            raise AttemptExpired(attempt_id)
        return self._record(row)

    def cancel(self, attempt_id: str) -> AttemptRecord:
        expired = False
        with self._connection() as connection:
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
                ).fetchone()
                if row is None:
                    raise AttemptNotFound(attempt_id)

                now = self._now()
                expired = self._mark_expired(connection, row, now)
                if not expired:
                    record = self._record(row)
                    ciphertext, nonce = self._encrypt(
                        attempt_id, row["kind"], record.payload
                    )
                    connection.execute(
                        """
                        UPDATE attempts
                        SET status = 'cancelled', ciphertext = ?, nonce = ?,
                            updated_at = ?
                        WHERE id = ?
                        """,
                        (ciphertext, nonce, now, attempt_id),
                    )
                    row = connection.execute(
                        "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
                    ).fetchone()

        if expired:
            raise AttemptExpired(attempt_id)
        return self._record(row)

    def delete(self, attempt_id: str) -> None:
        with self._connection() as connection:
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    "DELETE FROM attempts WHERE id = ?", (attempt_id,)
                )
                if cursor.rowcount == 0:
                    raise AttemptNotFound(attempt_id)

    def purge_expired(self) -> int:
        with self._connection() as connection:
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                now = self._now()
                cursor = connection.execute(
                    """
                    UPDATE attempts
                    SET status = 'expired', updated_at = ?
                    WHERE expires_at <= ? AND status != 'expired'
                    """,
                    (now, now),
                )
                return cursor.rowcount

    def close(self) -> None:
        with self._lock:
            self._closed = True

    def __enter__(self) -> AttemptStore:
        with self._lock:
            if self._closed:
                raise RuntimeError("attempt store is closed")
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

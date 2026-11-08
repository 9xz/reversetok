import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from reversetok.store import (
    AttemptConflict,
    AttemptExpired,
    AttemptNotFound,
    AttemptStore,
)


class AttemptStoreTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "nested" / "attempts.sqlite3"
        self.key = bytes(range(32))
        self.store = AttemptStore(self.path, self.key)

    def tearDown(self):
        self.store.close()
        self.tempdir.cleanup()

    def create_attempt(self, kind="signup", idempotency_key="request-1", ttl=60):
        return self.store.create(
            kind,
            {"email": "person@example.com", "step": 1},
            idempotency_key,
            ttl,
        )

    def raw_row(self, attempt_id):
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            return connection.execute(
                "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()

    def test_idempotency_returns_existing_attempt(self):
        first = self.create_attempt()
        second = self.store.create(
            "signup",
            {"email": "different@example.com", "step": 99},
            "request-1",
            300,
        )

        self.assertEqual(second.id, first.id)
        self.assertEqual(second.payload, first.payload)
        self.assertEqual(second.created_at, first.created_at)
        self.assertEqual(second.expires_at, first.expires_at)
        with closing(sqlite3.connect(self.path)) as connection:
            count = connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]
        self.assertEqual(count, 1)

    def test_record_and_encrypted_payload_persist_across_reopen(self):
        created = self.create_attempt()
        self.store.close()
        self.store.close()

        self.store = AttemptStore(self.path, self.key)
        loaded = self.store.get(created.id)

        self.assertEqual(loaded, created)
        self.assertEqual(loaded.payload["email"], "person@example.com")

    def test_update_changes_status_payload_and_expiry(self):
        with patch("reversetok.store.time.time", return_value=1_700_000_000):
            created = self.create_attempt(ttl=60)
        original_nonce = bytes(self.raw_row(created.id)["nonce"])

        with patch("reversetok.store.time.time", return_value=1_700_000_005):
            updated = self.store.update(
                created.id,
                "completed",
                {"email": "person@example.com", "step": 2},
                expected_statuses={"pending"},
                extend_expiry=30,
            )

        self.assertEqual(updated.status, "completed")
        self.assertEqual(updated.payload["step"], 2)
        self.assertEqual(updated.created_at, created.created_at)
        self.assertEqual(updated.updated_at, 1_700_000_005)
        self.assertEqual(updated.expires_at, created.expires_at + 30)
        self.assertNotEqual(bytes(self.raw_row(created.id)["nonce"]), original_nonce)
        with patch("reversetok.store.time.time", return_value=1_700_000_005):
            self.assertEqual(self.store.get(created.id), updated)

    def test_expected_status_conflict_leaves_record_unchanged(self):
        created = self.create_attempt()

        with self.assertRaises(AttemptConflict):
            self.store.update(
                created.id,
                "completed",
                {"secret": "replacement"},
                expected_statuses={"running"},
            )

        self.assertEqual(self.store.get(created.id), created)

    def test_expired_update_and_get_mark_attempt_expired(self):
        with patch("reversetok.store.time.time", return_value=2_000_000_000):
            created = self.create_attempt(ttl=5)

        with patch("reversetok.store.time.time", return_value=2_000_000_005):
            with self.assertRaises(AttemptExpired):
                self.store.update(created.id, "completed", {"step": 2})
            self.assertEqual(self.raw_row(created.id)["status"], "expired")
            with self.assertRaises(AttemptExpired):
                self.store.get(created.id)

    def test_cancel_preserves_payload(self):
        created = self.create_attempt()

        cancelled = self.store.cancel(created.id)

        self.assertEqual(cancelled.status, "cancelled")
        self.assertEqual(cancelled.payload, created.payload)
        self.assertEqual(self.store.get(created.id), cancelled)

    def test_delete_hard_deletes_attempt(self):
        created = self.create_attempt()

        self.store.delete(created.id)

        self.assertIsNone(self.raw_row(created.id))
        with self.assertRaises(AttemptNotFound):
            self.store.get(created.id)

    def test_purge_marks_only_currently_expired_records(self):
        with patch("reversetok.store.time.time", return_value=3_000_000_000):
            expired = self.create_attempt(idempotency_key="short", ttl=5)
            active = self.create_attempt(idempotency_key="long", ttl=60)

        with patch("reversetok.store.time.time", return_value=3_000_000_005):
            self.assertEqual(self.store.purge_expired(), 1)
            self.assertEqual(self.store.purge_expired(), 0)
            self.assertEqual(self.raw_row(expired.id)["status"], "expired")
            self.assertEqual(self.store.get(active.id).status, "pending")

    def test_ciphertext_does_not_contain_plaintext_secret(self):
        secret = "unique-plaintext-secret-7f56e20a"
        created = self.store.create("signup", {"secret": secret}, "secret-request", 60)

        row = self.raw_row(created.id)

        self.assertNotIn(secret.encode("utf-8"), bytes(row["ciphertext"]))
        self.assertEqual(len(bytes(row["nonce"])), 12)
        self.assertEqual(self.store.get(created.id).payload["secret"], secret)

    def test_key_and_time_intervals_are_validated(self):
        for key_length in (0, 16, 31, 33):
            with self.subTest(key_length=key_length):
                with self.assertRaises(ValueError):
                    AttemptStore(self.path, b"k" * key_length)

        with self.assertRaises(ValueError):
            self.create_attempt(ttl=0)

        created = self.create_attempt(idempotency_key="valid-ttl")
        with self.assertRaises(ValueError):
            self.store.update(
                created.id, "completed", created.payload, extend_expiry=0
            )


if __name__ == "__main__":
    unittest.main()

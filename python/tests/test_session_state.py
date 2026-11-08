from datetime import datetime, timedelta, timezone
import unittest

from wreq import Cookie, Jar, SameSite

from reversetok.session_state import dump_cookie_jar, restore_cookie_jar


class CookieSnapshotTests(unittest.TestCase):
    def test_round_trip_preserves_attributes_and_host_only_origin(self):
        jar = Jar()
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        jar.add(Cookie("flow", "secret", path="/"), "https://example.com/start")
        jar.add(
            Cookie(
                "shared",
                "yes",
                domain="example.com",
                path="/account",
                expires=expires,
                http_only=True,
                secure=True,
                same_site=SameSite.Lax,
            ),
            "https://example.com/start",
        )
        snapshots = dump_cookie_jar(jar, ["https://example.com/start"])
        restored = Jar()
        restore_cookie_jar(restored, snapshots)

        flow = restored.get("flow", "https://example.com/")
        self.assertIsNotNone(flow)
        self.assertEqual(flow.value, "secret")
        shared = restored.get("shared", "https://example.com/account")
        self.assertIsNotNone(shared)
        self.assertEqual(shared.domain, "example.com")
        self.assertEqual(shared.path, "/account")
        self.assertEqual(shared.expires, expires)
        self.assertTrue(shared.http_only)
        self.assertTrue(shared.secure)
        self.assertTrue(shared.same_site_lax)
        self.assertEqual(next(item for item in snapshots if item["name"] == "flow")["url"], "https://example.com/")

    def test_missing_host_only_origin_fails_instead_of_dropping_cookie(self):
        jar = Jar()
        jar.add(Cookie("flow", "secret", path="/"), "https://other.example/start")
        with self.assertRaisesRegex(RuntimeError, "host-only origin"):
            dump_cookie_jar(jar, ["https://example.com/start"])


if __name__ == "__main__":
    unittest.main()

import base64
import unittest

from reversetok import MetaSecSigner, extract_dynamic_fields


class DynamicExtractionTests(unittest.TestCase):
    def setUp(self):
        self.url = "https://example.invalid/path?aid=1233&probe=dynamic"
        self.body = b"probe"
        signer = MetaSecSigner({
            "deviceId": "1",
            "installId": "2",
            "dynSeed": base64.b64encode(bytes([7] * 16)).decode("ascii"),
            "dynVersion": 6,
            "seedState": 3,
            "f26Tail": [
                {"algorithm": 229, "outputHex": "deadbeef"},
                {"algorithm": 547, "outputHex": "01020304"},
            ],
        })
        signed = signer.sign_request(self.url, body=self.body, nowSeconds=1700000000, nonce=7)
        self.argus = signed["headers"]["X-Argus"]

    def test_validates_and_returns_native_task_entries(self):
        fields = extract_dynamic_fields(self.argus, self.url, body=self.body)
        self.assertEqual(fields["dynVersion"], 6)
        self.assertEqual(fields["seedState"], 3)
        self.assertEqual(fields["nonce"], 7)
        self.assertEqual(fields["nowSeconds"], 1700000000)
        self.assertEqual(fields["f26Tail"], [
            {"algorithm": 229, "outputHex": "deadbeef"},
            {"algorithm": 547, "outputHex": "01020304"},
        ])

    def test_rejects_task_state_from_another_query(self):
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            extract_dynamic_fields(
                self.argus,
                "https://example.invalid/path?aid=1233&probe=other",
                body=self.body,
            )


if __name__ == "__main__":
    unittest.main()

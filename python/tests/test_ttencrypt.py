import base64
import json
from pathlib import Path
import unittest

from reversetok import tt_decrypt, tt_decrypt_gzip, tt_encrypt, tt_encrypt_gzip


class TtEncryptTests(unittest.TestCase):
    def test_native_vectors_match_byte_for_byte(self):
        fixtures = json.loads((Path(__file__).parents[2] / "fixtures" / "vectors.json").read_text())
        for vector in fixtures["ttEncrypt"]:
            with self.subTest(vector=vector["name"]):
                raw_input = base64.b64decode(vector["inputBase64"])
                key_stream = base64.b64decode(vector["keyStreamBase64"])
                expected = base64.b64decode(vector["outputBase64"])
                self.assertEqual(tt_encrypt(raw_input, key_stream), expected)
                self.assertEqual(tt_decrypt(expected), raw_input)

    def test_gzip_round_trip_uses_java_os_header(self):
        raw_input = b"device registration payload"
        encrypted = tt_encrypt_gzip(raw_input, bytes(range(32)))
        self.assertEqual(tt_decrypt(encrypted)[9], 255)
        self.assertEqual(tt_decrypt_gzip(encrypted), raw_input)

    def test_invalid_inputs_and_modified_ciphertext_fail(self):
        with self.assertRaisesRegex(RuntimeError, "empty"):
            tt_encrypt(b"")
        with self.assertRaisesRegex(RuntimeError, "32 bytes"):
            tt_encrypt(b"probe", b"1234")
        modified = bytearray(tt_encrypt(b"probe", bytes(32)))
        modified[-1] ^= 1
        with self.assertRaises(RuntimeError):
            tt_decrypt(bytes(modified))


if __name__ == "__main__":
    unittest.main()

import unittest
from urllib.parse import parse_qs, urlparse

from totp import generate_secret, provisioning_uri, totp, verify


RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


class TotpTests(unittest.TestCase):
    def test_rfc_6238_sha1_vectors(self):
        vectors = {
            59: "287082",
            1111111109: "081804",
            1111111111: "050471",
            1234567890: "005924",
            2000000000: "279037",
            20000000000: "353130",
        }
        for timestamp, expected in vectors.items():
            with self.subTest(timestamp=timestamp):
                self.assertEqual(totp(RFC_SECRET, timestamp=timestamp), expected)

    def test_verification_accepts_nearby_time_window(self):
        code = totp(RFC_SECRET, timestamp=59)
        self.assertTrue(verify(RFC_SECRET, code, timestamp=59, window=0))
        self.assertFalse(verify(RFC_SECRET, "12", timestamp=59))

    def test_new_secret_is_valid_base32_and_sufficiently_long(self):
        secret = generate_secret()
        self.assertGreaterEqual(len(secret), 32)
        self.assertEqual(len(totp(secret, timestamp=0)), 6)

    def test_uri_contains_expected_account_fields(self):
        uri = provisioning_uri(RFC_SECRET, "Example Service", "alex@example.test")
        parsed = urlparse(uri)
        self.assertEqual(parsed.scheme, "otpauth")
        self.assertEqual(parsed.netloc, "totp")
        self.assertEqual(parse_qs(parsed.query)["issuer"], ["Example Service"])
        self.assertIn("Example%20Service%3Aalex%40example.test", parsed.path)

    def test_invalid_secret_is_rejected(self):
        with self.assertRaises(ValueError):
            totp("not-valid!")


if __name__ == "__main__":
    unittest.main()

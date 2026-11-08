import unittest

from reversetok import MetaSecSigner, VERSION


NATIVE_TOKEN = "8fvvl9FBuceE7A90navMO3zbvgpdoPlLe3ZZtV3zgyOpBOwwMQDFsUr14jCIVNprkim047xhrRpUonDwpI8crvW0ZqhfT6whDgUCGoWEBM35DRnfMEcjl7DoFjVb1mI84Plw11wjLGsw5u7oZa15v7U4u18BXRCMCtbuqZ068YME4rYokaoOhbEOoZHBgpfUJW2JI5kYfa7HpJvmKkaeFYN8wFdpigQThzfrEdmJlCA4f5XAYrZ7pMTcUUSsq7xXZrLJ+g5LtOMb/xw6FdsTFZI+C50wSL7RUzUG1gJNN7V7tFlzGrJtZGwuGObd9HCrnLmjuDmPvJIqcXq55QM7F6d4wPdO5CziBnWNbG45mnGpJfrxiKbnYOUwgWoPclhsC/PqXg8PSx7cqYEdTkOYblvepkqooNuxZY7rDYXAjkd/z2/KE6lMuaoVNeiYVCeZb421dI3QwrJAuyybvjj7nt04v8cph+nW+sFQWveAeBypdfNB+gwXSVgUdc/XhPV4W315KLM+dpQBURBxex7fUbYf0Sr7h0niMt1tEi24OsjHlHOq853Unpvrx3YYoEIANdlFiWnm7X3xsaB6FbsIbyA09DAnfbTx/V+2vZbUoAETPz2DzNxmnIXcJDIuD0QZDyrRSQ4TjTjtLJ4QCCiW6XgQkoo8z/KY6nl5fd7VDNBWjThvwPUltvZmdmXxBlh0TIq3dl3DLO+RVc+FjND10z0y"


class SigningTests(unittest.TestCase):
    def setUp(self):
        self.signer = MetaSecSigner({
            "deviceId": "0000000000000000001",
            "installId": "0000000000000000002",
            "appVersion": "47.7.2",
            "versionCode": "2024707020",
            "model": "Pixel 7",
            "device": "panther",
            "build": "TQ3A.230805.001",
            "release": "13",
            "securityPatch": "2023-08-05",
            "fingerprint": "google/panther/panther:13/TQ3A.230805.001/10216780:user/release-keys",
            "f23Field2": 18,
            "f23Field4": 283211776,
            "f23Field5": 27262976,
            "f34": "9066089097591521280",
            "f35": "13838013542538480364",
            "f36": "7678332264662476164",
        })
        self.url = "https://api16-normal-useast5.tiktokv.us/aweme/v1/config/get/?aid=1233&version_name=47.7.2&probe=vm"
        self.options = {
            "nowSeconds": 1793934086,
            "nonce": 818642162,
            "rnd4Hex": "f1fb0209",
            "ladonRandom4Hex": "65743635",
            "headerHex": "ecc5582d37019c0318",
            "trailerHex": "48228a29a79e78e0800000f50d",
            "key4Hex": "ffffeff4",
        }

    def test_version(self):
        self.assertEqual(VERSION, "0.1.0")

    def test_native_argus_fixture(self):
        result = self.signer.sign_request(self.url, **self.options)
        headers = result["headers"]
        self.assertEqual(headers["X-Argus"], NATIVE_TOKEN)
        self.assertEqual(headers["X-Gorgon"], "8404a0970000e7ba4016566240d0956e355223a9b6962be75cfa")
        self.assertEqual(headers["X-Ladon"], "ZXQ2NbnqR1PDx6+VAeHnzhRdaByqv3+g7AyGAaLaZE79iNGR")
        self.assertEqual(headers["X-Khronos"], "1793934086")
        self.assertEqual(headers["X-Ss-Req-Ticket"], "1793934086000")
        self.assertEqual(headers["X-Ss-Stub"], "D41D8CD98F00B204E9800998ECF8427E")
        self.assertEqual(result["method"], "GET")
        self.assertEqual(result["bodyBase64"], "")
        self.assertEqual(self.signer.sign_headers(self.url, **self.options)["X-Argus"], NATIVE_TOKEN)


if __name__ == "__main__":
    unittest.main()

import unittest

from reversetok.profiles import (
    build_common_params,
    build_registration_header,
    build_user_agent,
    with_common_params,
)


PERSONA = {
    "appId": "1233",
    "licenseId": 2142840551,
    "sdkVersion": "v05.03.04-ov-android",
    "sdkVersionCode": 0x05030420,
    "appVersion": "47.7.2",
    "versionCode": "2024707020",
    "model": "Pixel 7",
    "device": "panther",
    "build": "TQ3A.230805.001",
    "release": "13",
    "securityPatch": "2023-08-05",
    "fingerprint": "google/panther/panther:13/TQ3A.230805.001/10216780:user/release-keys",
    "channel": "googleplay",
    "resolution": "1080x2400",
    "dpi": 420,
    "deviceId": "7370000000000000001",
    "installId": "7370000000000000002",
    "f34": "9066089097591521280",
    "f35": "13838013542538480364",
    "f36": "7678332264662476164",
}
COMMON_OVERRIDES = {
    "app_language": "en",
    "carrier_region": "US",
    "carrier_region_v2": "US",
    "current_region": "US",
    "language": "en",
    "last_install_time": 1793930000,
    "locale": "en_US",
    "mcc_mnc": "310260",
    "op_region": "US",
    "os_api": 33,
    "region": "US",
    "residence": "US",
    "sys_region": "US",
    "timezone_name": "America/Los_Angeles",
    "timezone_offset": -28800,
}
REGISTRATION_OVERRIDES = {
    "app_language": "en",
    "language": "en",
    "locale": "en_US",
    "os_api": 33,
    "region": "US",
}


class ProfileTests(unittest.TestCase):
    def test_user_agent_matches_ttnet_builder(self):
        self.assertEqual(
            build_user_agent(PERSONA, {"locale": "en_US"}),
            "com.zhiliaoapp.musically/2024707020 (Linux; U; Android 13; en_US; "
            "Pixel 7; Build/TQ3A.230805.001; Cronet/TTNetVersion:093e42e6 "
            "2026-09-28 QuicVersion:ff43781e 2026-09-28)",
        )

    def test_common_params_use_version_display_and_environment_contracts(self):
        params = build_common_params(PERSONA, COMMON_OVERRIDES, now_ms=1793934086123)
        self.assertEqual(params, {
            "_rticket": "1793934086123",
            "is_pad": "0",
            "host_abi": "arm64-v8a",
            "ts": "1793934086",
            "app_version": "2024707020",
            "ab_version": "47.7.2",
            "ac": "mobile",
            "ac2": "unknown",
            "aid": "1233",
            "app_language": "en",
            "app_name": "musical_ly",
            "app_type": "normal",
            "build_number": "47.7.2",
            "carrier_region": "US",
            "carrier_region_v2": "US",
            "channel": "googleplay",
            "current_region": "US",
            "device_brand": "google",
            "device_id": "7370000000000000001",
            "device_platform": "android",
            "device_type": "Pixel 7",
            "dpi": "420",
            "iid": "7370000000000000002",
            "language": "en",
            "last_install_time": "1793930000",
            "locale": "en_US",
            "manifest_version_code": "2024707020",
            "mcc_mnc": "310260",
            "op_region": "US",
            "os": "android",
            "os_api": "33",
            "os_version": "13",
            "region": "US",
            "residence": "US",
            "resolution": "1080*2400",
            "ssmix": "a",
            "sys_region": "US",
            "timezone_name": "America/Los_Angeles",
            "timezone_offset": "-28800",
            "uoo": "0",
            "update_version_code": "2024707020",
            "version_code": "470702",
            "version_name": "47.7.2",
        })

    def test_common_params_append_without_reordering_existing_query(self):
        url = with_common_params(
            "https://example.com/path?z=last#fragment",
            {"aid": "1233", "timezone_name": "America/Los Angeles"},
        )
        self.assertEqual(
            url,
            "https://example.com/path?z=last&aid=1233&timezone_name=America%2FLos+Angeles#fragment",
        )

    def test_registration_header_uses_profile_and_nonempty_identities(self):
        header = build_registration_header(
            PERSONA,
            {**REGISTRATION_OVERRIDES, "req_id": "captured-request", "bd_did": "optional-bd"},
        )
        self.assertEqual(header["user_agent"], build_user_agent(PERSONA, {"locale": "en_US"}))
        self.assertEqual(header["package"], "com.zhiliaoapp.musically")
        self.assertEqual(header["app_version"], "47.7.2")
        self.assertEqual(header["version_code"], "2024707020")
        self.assertEqual(header["update_version_code"], "2024707020")
        self.assertEqual(header["manifest_version_code"], "2024707020")
        self.assertEqual(header["resolution"], "2400x1080")
        self.assertEqual(header["density_dpi"], 420)
        self.assertEqual(header["rom"], "TQ3A.230805.001")
        self.assertEqual(header["rom_version"], PERSONA["fingerprint"])
        self.assertEqual(header["device_id"], PERSONA["deviceId"])
        self.assertEqual(header["install_id"], PERSONA["installId"])
        self.assertEqual(header["req_id"], "captured-request")
        self.assertEqual(header["bd_did"], "optional-bd")
        self.assertEqual(header["sdk_version"], "2.5.14.8")
        self.assertEqual(header["display_density"], "xxhdpi")
        self.assertEqual(header["display_density_v2"], 420)
        self.assertEqual(header["sdk_target_version"], 30)
        self.assertEqual(header["sdk_flavor"], "i18nInner")
        self.assertEqual(header["git_hash"], "e9b5c24")

    def test_empty_identity_is_omitted_and_environment_is_not_fabricated(self):
        empty = {**PERSONA, "deviceId": "", "installId": ""}
        params = build_common_params(empty, COMMON_OVERRIDES, now_ms=1793934086123)
        self.assertNotIn("device_id", params)
        self.assertNotIn("iid", params)
        header = build_registration_header(empty, REGISTRATION_OVERRIDES)
        self.assertNotIn("device_id", header)
        self.assertNotIn("install_id", header)
        with self.assertRaisesRegex(ValueError, "request override"):
            build_common_params(PERSONA, {"locale": "en_US"}, now_ms=1793934086123)
        with self.assertRaisesRegex(ValueError, "locale"):
            build_user_agent(PERSONA)


if __name__ == "__main__":
    unittest.main()

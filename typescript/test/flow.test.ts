import { createServer } from "node:http";
import { describe, expect, test } from "bun:test";
import {
  buildCommonParams,
  buildRegistrationHeader,
  buildUserAgent,
  createWreqSession,
  DeviceRegistrationClient,
  mixDecode,
  mixEncode,
  SignupClient,
  ttDecryptGzip,
  type Persona,
} from "../src/index";

const PERSONA: Persona = {
  deviceId: "7705612319771035149",
  installId: "7705612484128982798",
  appId: "1233",
  appVersion: "47.7.2",
  versionCode: "2024707020",
  model: "Pixel 7",
  device: "panther",
  build: "TQ3A.230805.001",
  release: "13",
  securityPatch: "2023-08-05",
  fingerprint: "google/panther/panther:13/TQ3A.230805.001/10216780:user/release-keys",
  channel: "googleplay",
  resolution: "1080x2400",
  dpi: 420,
};

const COMMON_OVERRIDES = {
  app_language: "en",
  carrier_region: "US",
  carrier_region_v2: "310",
  current_region: "US",
  language: "en",
  last_install_time: 1793930000,
  locale: "en_US",
  mcc_mnc: "310410",
  op_region: "US",
  os_api: 33,
  region: "US",
  residence: "US",
  sys_region: "US",
  timezone_name: "America/Los_Angeles",
  timezone_offset: -25200,
};

describe("profiles, registration, and signup flow (pure TypeScript)", () => {
  test("builds user agent, common params, and registration header", () => {
    const ua = buildUserAgent(PERSONA, { locale: "en_US" });
    expect(ua).toContain("com.zhiliaoapp.musically/2024707020");
    expect(ua).toContain("Pixel 7; Build/TQ3A.230805.001");
    const params = buildCommonParams(PERSONA, COMMON_OVERRIDES, { nowMs: 1793934086123 });
    expect(params.version_code).toBe("470702");
    expect(params.resolution).toBe("1080*2400");
    const regHeader = buildRegistrationHeader(PERSONA, {
      app_language: "en",
      language: "en",
      locale: "en_US",
      os_api: 33,
      region: "US",
    });
    expect(regHeader.display_density).toBe("xxhdpi");
    expect(regHeader.resolution).toBe("2400x1080");
    expect(mixDecode(mixEncode("+1 2093761190"))).toBe("+1 2093761190");
    expect(mixEncode("24")).toBe("3731");
  });

  test("registers device, completes mobile signup, and sends TicketGuard headers on post-signup routes", async () => {
    const seenRequests: { path: string; headers: Record<string, string>; body: Buffer }[] = [];
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        const body = Buffer.concat(chunks);
        const url = new URL(req.url ?? "/", "http://127.0.0.1");
        const headers: Record<string, string> = {};
        for (const [k, v] of Object.entries(req.headers)) {
          if (typeof v === "string") headers[k.toLowerCase()] = v;
        }
        seenRequests.push({ path: url.pathname, headers, body });

        if (url.pathname === "/service/2/device_register/") {
          const decrypted = JSON.parse(ttDecryptGzip(body).toString("utf8"));
          expect(decrypted.magic_tag).toBe("ss_app_log");
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ device_id: "7705855445101987341", install_id: "7705855689151727373" }));
          return;
        }
        if (url.pathname === "/passport/mobile/send_code/v1/") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ message: "success", data: { has_account: false, retry_time: 60, mobile_ticket: "mt_1" } }));
          return;
        }
        if (url.pathname === "/passport/mobile/sms_login_only/") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ message: "error", data: { error_code: 1011, sms_code_key: "sck_1" } }));
          return;
        }
        if (url.pathname === "/passport/mobile/sms_login_continue/") {
          const tgServer = Buffer.from(
            JSON.stringify({
              tickets: [{ ticket: "tg-ticket-ts", ts_sign: JSON.stringify({ ts_sign_ree: "ree-sig-ts" }) }],
            }),
            "utf8",
          ).toString("base64");
          res.writeHead(200, {
            "content-type": "application/json",
            "x-tt-token": "ts-session-token",
            "tt-ticket-guard-server-data": tgServer,
          });
          res.end(JSON.stringify({ message: "success", data: { user_id_str: "7705855766996042766", new_user: 1 } }));
          return;
        }
        if (url.pathname === "/aweme/v1/commit/user/") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ status_code: 0, status_msg: "", user: { nickname: "Alex", signature: "CA", unique_id: "alex" } }));
          return;
        }
        if (url.pathname === "/passport/login_name/update/") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ message: "success", data: { login_name: "alex_handle" } }));
          return;
        }
        if (url.pathname === "/passport/token/beat/v2/") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ message: "success", data: {} }));
          return;
        }
        if (url.pathname === "/passport/account/info/v2/") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ message: "success", data: { user_id_str: "7705855766996042766", screen_name: "alex_handle" } }));
          return;
        }
        res.writeHead(404).end();
      });
    });

    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    if (!addr || typeof addr === "string") throw new Error("missing server address");
    const baseUrl = `http://127.0.0.1:${addr.port}`;

    const session = await createWreqSession({ ...PERSONA, deviceId: "", installId: "", allowEmptyIdentity: true });
    try {
      const regClient = new DeviceRegistrationClient(session, session.getPersona(), {
        overrides: { app_language: "en", language: "en", locale: "en_US", os_api: 33, region: "US" },
        endpoint: `${baseUrl}/service/2/device_register/`,
      });
      const identity = await regClient.register();
      expect(identity.deviceId).toBe("7705855445101987341");
      expect(session.getPersona().deviceId).toBe("7705855445101987341");

      const signup = new SignupClient(session, { baseUrl });
      const started = await signup.startMobile("+1 2093761190", 24);
      expect(started.status).toBe("needs_otp");

      const completed = await signup.completeMobileLoginOnly("943197", { birthday: "1999-05-14", carrierRegion: "US" });
      expect(completed.status).toBe("completed");

      const profile = await signup.commitUserProfile({ nickname: "Alex", signature: "CA" });
      expect(profile.nickname).toBe("Alex");

      const updated = await signup.updateLoginName("alex_handle");
      expect(updated.uniqueId).toBe("alex_handle");

      const beat = await signup.tokenBeat({ scene: "boot", firstBeat: true });
      expect(beat.tokenBeatScene).toBe("boot");

      const info = await signup.getAccountInfo({ scene: "login" });
      expect(info.accountUserId).toBe("7705855766996042766");

      const commitReq = seenRequests.find((r) => r.path === "/aweme/v1/commit/user/");
      expect(commitReq?.headers["x-tt-token"]).toBe("ts-session-token");
      expect(commitReq?.headers["tt-ticket-guard-version"]).toBe("3");
      expect(commitReq?.headers["tt-ticket-guard-public-key"]).toBeDefined();
      expect(commitReq?.headers["tt-ticket-guard-client-data"]).toBeDefined();
    } finally {
      await session.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

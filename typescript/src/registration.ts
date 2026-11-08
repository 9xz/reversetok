import { gunzipSync } from "node:zlib";

import { buildRegistrationHeader, type ProfileOverrides, withCommonParams } from "./profiles";
import { ttEncryptGzip } from "./ttencrypt";
import type { Persona } from "./types";
import type { ReplayOptions, WreqSession } from "./wreq";

export class RegistrationResponseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RegistrationResponseError";
  }
}

export const DEFAULT_REGISTRATION_URL = "https://log-va.tiktokv.com/service/2/device_register/";

export interface RegistrationIdentity {
  deviceId: string;
  installId: string;
  bdDid?: string;
  ssid?: string;
  deviceToken?: string;
}

export interface DeviceRegistrationOptions {
  commonHeaders?: Record<string, string>;
  overrides?: ProfileOverrides;
  queryParams?: Record<string, string | number>;
  endpoint?: string;
}

export interface RegisterCallOptions {
  nowMs?: number;
  replay?: ReplayOptions;
  updateSessionPersona?: boolean;
}

function requiredIdentity(payload: Record<string, unknown>, key: string): string {
  const val = payload[key];
  if (typeof val === "boolean" || (typeof val !== "string" && typeof val !== "number") || val === "") {
    throw new RegistrationResponseError(`device registration response requires ${key}`);
  }
  return String(val);
}

function parseIdentity(payload: unknown): RegistrationIdentity {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new RegistrationResponseError("device registration response must be a JSON object");
  }
  const obj = payload as Record<string, unknown>;
  const deviceId =
    obj.device_id !== undefined && obj.device_id !== null && obj.device_id !== ""
      ? requiredIdentity(obj, "device_id")
      : requiredIdentity(obj, "device_id_str");
  const installId = requiredIdentity(obj, "install_id");
  if (deviceId === "0" || installId === "0") {
    throw new RegistrationResponseError("device registration returned a placeholder identity");
  }
  const result: RegistrationIdentity = { deviceId, installId };
  const optionalMap = {
    bd_did: "bdDid",
    ssid: "ssid",
    device_token: "deviceToken",
  } as const;
  for (const [wireKey, propKey] of Object.entries(optionalMap) as [keyof typeof optionalMap, "bdDid" | "ssid" | "deviceToken"][]) {
    const val = obj[wireKey];
    if (val === undefined || val === null) continue;
    if (typeof val === "boolean" || (typeof val !== "string" && typeof val !== "number")) {
      throw new RegistrationResponseError(`device registration response field ${wireKey} must be a string or integer`);
    }
    result[propKey] = String(val);
  }
  return result;
}

export class DeviceRegistrationClient {
  private persona: Persona;
  private readonly commonHeaders: Record<string, string>;
  private readonly overrides: ProfileOverrides;
  private readonly queryParams: Record<string, string | number>;
  private readonly endpoint: string;

  constructor(
    private readonly session: WreqSession,
    persona: Persona,
    options: DeviceRegistrationOptions = {},
  ) {
    this.persona = {
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
      ...persona,
    };
    this.commonHeaders = { ...(options.commonHeaders ?? {}) };
    const rawOverrides = options.overrides ?? {};
    const lang = String(rawOverrides.language ?? String(rawOverrides.locale ?? "en_US").split("_")[0]);
    this.overrides = {
      app_language: lang,
      language: lang,
      locale: "en_US",
      os_api: 33,
      region: "US",
      ...rawOverrides,
    };
    this.queryParams = { ...(options.queryParams ?? {}) };
    this.endpoint = options.endpoint ?? DEFAULT_REGISTRATION_URL;
  }

  async register(options: RegisterCallOptions = {}): Promise<RegistrationIdentity> {
    if (this.persona.allowEmptyIdentity !== true && (!this.persona.deviceId || !this.persona.installId)) {
      throw new Error("deviceId and installId are required unless persona allowEmptyIdentity is true");
    }
    const nowMs = options.nowMs ?? Date.now();
    if (!Number.isInteger(nowMs) || nowMs < 0) {
      throw new Error("nowMs must be a nonnegative integer");
    }
    const envelope = {
      magic_tag: "ss_app_log",
      header: buildRegistrationHeader(this.persona, this.overrides),
      time_sync: {},
      _gen_time: nowMs,
    };
    const encrypted = ttEncryptGzip(Buffer.from(JSON.stringify(envelope), "utf8"));
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(this.commonHeaders)) {
      headers[k.toLowerCase()] = v;
    }
    headers["content-type"] = "application/octet-stream;tt-data=a";
    headers["accept-encoding"] = "gzip";

    const response = await this.session.fetch(withCommonParams(this.endpoint, this.queryParams), {
      method: "POST",
      headers,
      body: encrypted,
      replay: options.replay,
    });
    if (!response.ok) {
      throw new Error(`device registration failed with HTTP ${response.status}: ${await response.text()}`);
    }
    const rawBytes = Buffer.from(await response.arrayBuffer());
    let decodedText: string;
    try {
      decodedText =
        rawBytes.length >= 2 && rawBytes[0] === 0x1f && rawBytes[1] === 0x8b
          ? gunzipSync(rawBytes).toString("utf8")
          : rawBytes.toString("utf8");
      const parsed = JSON.parse(decodedText);
      const identity = parseIdentity(parsed);
      this.persona = {
        ...this.persona,
        deviceId: identity.deviceId,
        installId: identity.installId,
        allowEmptyIdentity: false,
      };
      if (options.updateSessionPersona !== false) {
        this.session.updatePersona({
          deviceId: identity.deviceId,
          installId: identity.installId,
          allowEmptyIdentity: false,
        });
      }
      return identity;
    } catch (err) {
      if (err instanceof RegistrationResponseError) throw err;
      throw new RegistrationResponseError("device registration returned invalid JSON");
    }
  }
}

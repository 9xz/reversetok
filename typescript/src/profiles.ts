import type { Persona } from "./types";

export const PACKAGE = "com.zhiliaoapp.musically";
export const TTNET_VERSION = "093e42e6 2026-09-28";
export const QUIC_VERSION = "ff43781e 2026-09-28";

const COMMON_ENVIRONMENT_FIELDS = [
  "app_language",
  "carrier_region",
  "carrier_region_v2",
  "current_region",
  "language",
  "last_install_time",
  "locale",
  "mcc_mnc",
  "op_region",
  "os_api",
  "region",
  "residence",
  "sys_region",
  "timezone_name",
  "timezone_offset",
] as const;

export type CommonEnvironmentField = (typeof COMMON_ENVIRONMENT_FIELDS)[number];
export type ProfileOverrides = Record<string, string | number | boolean | null | undefined>;

function required(values: Record<string, unknown>, key: string): string | number {
  const val = values[key];
  if (val === undefined || val === null || val === "") {
    throw new Error(`persona field '${key}' is required`);
  }
  return val as string | number;
}

function environment(overrides: ProfileOverrides, key: string): string | number | boolean {
  const val = overrides[key];
  if (val === undefined || val === null) {
    throw new Error(`request override '${key}' is required`);
  }
  return val;
}

function dimensions(persona: Record<string, unknown>): [number, number] {
  const resolution = String(required(persona, "resolution"));
  const parts = resolution.split("x");
  if (parts.length !== 2) throw new Error("persona resolution must be WIDTHxHEIGHT");
  const width = Number.parseInt(parts[0]!, 10);
  const height = Number.parseInt(parts[1]!, 10);
  if (!Number.isInteger(width) || !Number.isInteger(height) || width <= 0 || height <= 0 || resolution !== `${width}x${height}`) {
    throw new Error("persona resolution must be WIDTHxHEIGHT");
  }
  return [width, height];
}

function shortVersionCode(appVersion: string): number {
  const parts = appVersion.split(".");
  if (parts.length !== 3) throw new Error("persona appVersion must be MAJOR.MINOR.PATCH");
  const major = Number.parseInt(parts[0]!, 10);
  const minor = Number.parseInt(parts[1]!, 10);
  const patch = Number.parseInt(parts[2]!, 10);
  if (
    !Number.isInteger(major) ||
    !Number.isInteger(minor) ||
    !Number.isInteger(patch) ||
    Math.min(major, minor, patch) < 0 ||
    minor > 99 ||
    patch > 99
  ) {
    throw new Error("persona appVersion must be MAJOR.MINOR.PATCH");
  }
  return (major * 100 + minor) * 100 + patch;
}

export function buildUserAgent(persona: Persona | Record<string, unknown>, overrides: ProfileOverrides = {}): string {
  const values: Record<string, unknown> = { ...persona, ...overrides };
  const locale = required(values, "locale");
  const pkg = values.package === undefined ? PACKAGE : String(values.package);
  if (!pkg) throw new Error("request override 'package' must not be empty");
  return `${pkg}/${required(values, "versionCode")} (Linux; U; Android ${required(values, "release")}; ${locale}; ${required(values, "model")}; Build/${required(values, "build")}; Cronet/TTNetVersion:${TTNET_VERSION} QuicVersion:${QUIC_VERSION})`;
}

export function buildCommonParams(
  persona: Persona | Record<string, unknown>,
  overrides: ProfileOverrides = {},
  options: { nowMs?: number } = {},
): Record<string, string> {
  const nowMs = options.nowMs ?? Date.now();
  if (!Number.isInteger(nowMs) || nowMs < 0) {
    throw new Error("nowMs must be a nonnegative integer");
  }
  const p = persona as Record<string, unknown>;
  const appVersion = String(required(p, "appVersion"));
  const versionCode = String(required(p, "versionCode"));
  const [width, height] = dimensions(p);
  const params: Record<string, unknown> = {
    _rticket: nowMs,
    is_pad: 0,
    host_abi: "arm64-v8a",
    ts: Math.floor(nowMs / 1000),
    app_version: versionCode,
    ab_version: appVersion,
    ac: "mobile",
    ac2: "unknown",
    aid: required(p, "appId"),
    app_name: "musical_ly",
    app_type: "normal",
    build_number: appVersion,
    channel: required(p, "channel"),
    device_brand: "google",
    device_platform: "android",
    device_type: required(p, "model"),
    dpi: required(p, "dpi"),
    manifest_version_code: versionCode,
    update_version_code: versionCode,
    os: "android",
    os_version: required(p, "release"),
    resolution: `${width}*${height}`,
    ssmix: "a",
    uoo: 0,
    version_code: shortVersionCode(appVersion),
    version_name: appVersion,
  };
  for (const key of COMMON_ENVIRONMENT_FIELDS) {
    params[key] = environment(overrides, key);
  }
  for (const [personaKey, wireKey] of [
    ["deviceId", "device_id"],
    ["installId", "iid"],
  ] as const) {
    const val = p[personaKey];
    if (val !== undefined && val !== null && val !== "") {
      params[wireKey] = val;
    }
  }
  Object.assign(params, overrides);
  const out: Record<string, string> = {};
  for (const [key, val] of Object.entries(params)) {
    if (val !== undefined && val !== null && val !== "") {
      out[key] = String(val);
    }
  }
  return out;
}

export function withCommonParams(url: string, commonParams: Record<string, string | number>): string {
  const entries = Object.entries(commonParams);
  if (entries.length === 0) return url;
  const search = new URLSearchParams();
  for (const [k, v] of entries) search.append(k, String(v));
  const encoded = search.toString();
  const hashIdx = url.indexOf("#");
  const base = hashIdx === -1 ? url : url.slice(0, hashIdx);
  const hash = hashIdx === -1 ? "" : url.slice(hashIdx);
  const sep = base.includes("?") ? "&" : "?";
  return `${base}${sep}${encoded}${hash}`;
}

export function buildRegistrationHeader(
  persona: Persona | Record<string, unknown>,
  overrides: ProfileOverrides = {},
): Record<string, unknown> {
  const p = persona as Record<string, unknown>;
  const appVersion = String(required(p, "appVersion"));
  const versionCode = String(required(p, "versionCode"));
  const [width, height] = dimensions(p);
  const dpi = Number(required(p, "dpi"));
  const buckets = [120, 160, 240, 320, 480, 640] as const;
  const nearest = buckets.reduce((best, b) => (Math.abs(b - dpi) < Math.abs(best - dpi) ? b : best), buckets[0]);
  const densityMap: Record<number, string> = {
    120: "ldpi",
    160: "mdpi",
    240: "hdpi",
    320: "xhdpi",
    480: "xxhdpi",
    640: "xxxhdpi",
  };

  const header: Record<string, unknown> = {
    channel: required(p, "channel"),
    not_request_sender: 1,
    aid: required(p, "appId"),
    user_agent: buildUserAgent(p, overrides),
    ab_version: appVersion,
    app_language: environment(overrides, "app_language"),
    package: overrides.package ?? PACKAGE,
    app_version: appVersion,
    version_code: versionCode,
    update_version_code: versionCode,
    manifest_version_code: versionCode,
    device_platform: "android",
    os: "Android",
    os_version: required(p, "release"),
    os_api: environment(overrides, "os_api"),
    device_model: required(p, "model"),
    device_brand: "google",
    device_manufacturer: "google",
    cpu_abi: "arm64-v8a",
    density_dpi: dpi,
    display_density: densityMap[nearest],
    display_density_v2: dpi,
    resolution: `${height}x${width}`,
    rom: required(p, "build"),
    rom_version: required(p, "fingerprint"),
    language: environment(overrides, "language"),
    region: environment(overrides, "region"),
    sdk_version: "2.5.14.8",
    sdk_target_version: 30,
    sdk_flavor: "i18nInner",
    git_hash: "e9b5c24",
  };
  for (const [personaKey, wireKey] of [
    ["deviceId", "device_id"],
    ["installId", "install_id"],
    ["deviceToken", "device_token"],
  ] as const) {
    const val = p[personaKey];
    if (val !== undefined && val !== null && val !== "") {
      header[wireKey] = val;
    }
  }
  Object.assign(header, overrides);
  for (const key of ["device_id", "install_id", "bd_did", "ssid", "device_token"]) {
    if (header[key] === undefined || header[key] === null || header[key] === "") {
      delete header[key];
    }
  }
  return header;
}

import { createPrivateKey, createPublicKey, createSign, generateKeyPairSync } from "node:crypto";
import { gunzipSync } from "node:zlib";

import { withCommonParams } from "./profiles";
import type { WreqSession, WreqSessionCookie } from "./wreq";

export function mixEncode(value: string): string {
  const bytes = Buffer.from(value, "utf8");
  const out = Buffer.alloc(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    out[i] = bytes[i]! ^ 5;
  }
  return out.toString("hex");
}

export function mixDecode(hexValue: string): string {
  const bytes = Buffer.from(hexValue, "hex");
  const out = Buffer.alloc(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    out[i] = bytes[i]! ^ 5;
  }
  return out.toString("utf8");
}

export class SignupError extends Error {
  readonly code: unknown;
  readonly data: unknown;
  readonly nextAction: string;

  constructor(
    message: string,
    options: { code?: unknown; data?: unknown; nextAction?: string } = {},
  ) {
    super(message);
    this.name = "SignupError";
    this.code = options.code;
    this.data = options.data;
    this.nextAction = options.nextAction ?? "failed";
  }
}

export interface SignupPublicState {
  status?: string;
  nextAction?: string;
  method?: "email" | "mobile";
  email?: string;
  mobile?: string;
  hasAccount?: boolean | null;
  retryTime?: number;
  age?: number;
  appealUrl?: string;
  verificationReason?: string;
  isPrompt?: boolean;
  registerAgeGatePostAction?: number;
  ageGatePostAction?: number;
  isMixedAge?: boolean;
  supplementAction?: number;
  needScreenTimeReminder?: boolean;
  loginName?: string;
  loginNameAvailable?: boolean;
  recommendedLoginNames?: string[];
  nickname?: string;
  signature?: string;
  avatarUri?: string;
  uniqueId?: string;
  accountUserId?: string;
  screenName?: string;
  tokenBeatScene?: string;
}

export interface SignupSnapshot {
  state: Record<string, unknown>;
  cookies: WreqSessionCookie[];
}

export interface SignupClientOptions {
  baseUrl?: string;
  state?: Record<string, unknown>;
  commonHeaders?: Record<string, string>;
  queryParams?: Record<string, string | number>;
}

const PUBLIC_STATE_FIELDS = [
  "status",
  "nextAction",
  "method",
  "email",
  "mobile",
  "hasAccount",
  "retryTime",
  "age",
  "appealUrl",
  "verificationReason",
  "isPrompt",
  "registerAgeGatePostAction",
  "ageGatePostAction",
  "isMixedAge",
  "supplementAction",
  "needScreenTimeReminder",
  "loginName",
  "loginNameAvailable",
  "recommendedLoginNames",
  "nickname",
  "signature",
  "avatarUri",
  "uniqueId",
  "accountUserId",
  "screenName",
  "tokenBeatScene",
] as const;

function createTicketGuardKeypair(existingPrivateKeyPem?: string): { privateKeyPem: string; publicKeyBase64: string } {
  const privateKey = existingPrivateKeyPem
    ? createPrivateKey(existingPrivateKeyPem)
    : generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey;
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const jwk = createPublicKey(privateKey).export({ format: "jwk" }) as { x: string; y: string };
  const x = Buffer.from(jwk.x, "base64url");
  const y = Buffer.from(jwk.y, "base64url");
  const uncompressed = Buffer.concat([Buffer.from([0x04]), x, y]);
  return { privateKeyPem, publicKeyBase64: uncompressed.toString("base64") };
}

function signTicketGuard(privateKeyPem: string, message: string): string {
  const signer = createSign("SHA256");
  signer.update(message, "utf8");
  signer.end();
  return signer.sign(privateKeyPem).toString("base64");
}

export class SignupClient {
  readonly state: Record<string, unknown>;
  private readonly baseUrl: string;
  private readonly commonHeaders: Record<string, string>;
  private readonly queryParams: Record<string, string | number>;
  private lastToken?: string;

  constructor(
    private readonly session: WreqSession,
    options: SignupClientOptions = {},
  ) {
    this.baseUrl = (options.baseUrl ?? "https://api16-normal-c-alisg.tiktokv.com").replace(/\/+$/, "");
    this.state = { ...(options.state ?? { status: "new", nextAction: "start" }) };
    this.commonHeaders = { ...(options.commonHeaders ?? {}) };
    this.queryParams = { ...(options.queryParams ?? {}) };
  }

  snapshot(): SignupSnapshot {
    return {
      state: { ...this.state },
      cookies: this.session.getAllCookies(),
    };
  }

  publicState(): SignupPublicState {
    const out: Record<string, unknown> = {};
    for (const key of PUBLIC_STATE_FIELDS) {
      if (key in this.state) out[key] = this.state[key];
    }
    return out as SignupPublicState;
  }

  private ensureTicketGuardKey(): { privateKeyPem: string; publicKeyBase64: string } {
    const existingPem = typeof this.state.ticketGuardPrivateKeyPem === "string" ? this.state.ticketGuardPrivateKeyPem : undefined;
    const existingPub = typeof this.state.ticketGuardPublicKey === "string" ? this.state.ticketGuardPublicKey : undefined;
    if (existingPem && existingPub) {
      return { privateKeyPem: existingPem, publicKeyBase64: existingPub };
    }
    const pair = createTicketGuardKeypair(existingPem);
    this.state.ticketGuardPrivateKeyPem = pair.privateKeyPem;
    this.state.ticketGuardPublicKey = pair.publicKeyBase64;
    return pair;
  }

  private captureTicketGuardServerData(rawHeader: string | null): void {
    if (!rawHeader) return;
    try {
      const decoded = JSON.parse(Buffer.from(rawHeader, "base64").toString("utf8")) as {
        tickets?: { ticket?: string; ts_sign?: string }[];
      };
      const item = decoded.tickets?.[0];
      if (item?.ticket) {
        this.state.ticketGuardTicket = item.ticket;
        const rawTs = item.ts_sign ?? "";
        let tsSignRee = rawTs;
        if (rawTs.startsWith("{")) {
          const parsed = JSON.parse(rawTs) as { ts_sign_ree?: string };
          if (parsed.ts_sign_ree) tsSignRee = parsed.ts_sign_ree;
        }
        this.state.ticketGuardTsSign = tsSignRee;
      }
    } catch {
      // Ignore malformed server data header
    }
  }

  private async request(
    path: string,
    fields: Record<string, string>,
    method: "GET" | "POST" = "POST",
  ): Promise<Record<string, unknown>> {
    const cleanPath = path.split("?")[0]!;
    const isPassport = cleanPath.startsWith("/passport/");
    const bodyFields: Record<string, string> = { ...fields };
    if (isPassport && method !== "GET") {
      bodyFields.account_sdk_source ??= "app";
      bodyFields.multi_login ??= "1";
    }
    const queryParams: Record<string, string | number> = { ...this.queryParams };
    if (isPassport) {
      queryParams["passport-sdk-version"] ??= "1";
      if (method === "GET") {
        queryParams.account_sdk_source ??= "app";
        queryParams.multi_login ??= "1";
      }
    }
    const url = withCommonParams(`${this.baseUrl}${path}`, queryParams);
    const headers: Record<string, string> = { ...this.commonHeaders };
    headers["sdk-version"] ??= "2";
    headers["x-tt-bypass-dp"] ??= "1";
    const { privateKeyPem, publicKeyBase64 } = this.ensureTicketGuardKey();
    headers["tt-ticket-guard-public-key"] ??= publicKeyBase64;
    headers["tt-ticket-guard-version"] ??= "3";
    headers["tt-ticket-guard-iteration-version"] ??= "0";

    if (typeof this.state.sessionToken === "string" && this.state.sessionToken.length > 0) {
      headers["x-tt-token"] ??= this.state.sessionToken;
      if (typeof this.state.ticketGuardTicket === "string" && this.state.ticketGuardTicket.length > 0) {
        const ts = Math.floor(Date.now() / 1000);
        const toSign = `ticket=${this.state.ticketGuardTicket}&path=${cleanPath}&timestamp=${ts}`;
        const reqSign = signTicketGuard(privateKeyPem, toSign);
        const clientData = {
          req_content: "ticket,path,timestamp",
          timestamp: ts,
          ts_sign: typeof this.state.ticketGuardTsSign === "string" ? this.state.ticketGuardTsSign : "",
          req_sign: reqSign,
        };
        headers["tt-ticket-guard-client-data"] ??= Buffer.from(JSON.stringify(clientData), "utf8").toString("base64");
      }
    }

    if (isPassport) {
      headers["passport-sdk-version"] ??= "1";
      headers["passport-sdk-settings"] ??= "x-tt-token";
      headers["passport-sdk-sign"] ??= "x-tt-token";
      headers["x-vc-bdturing-sdk-version"] ??= "2.4.4.i18n";
      const cookies = this.session.getCookies(url);
      const csrf = cookies.passport_csrf_token ?? cookies.passport_csrf_token_default;
      if (csrf) headers["x-tt-passport-csrf-token"] ??= csrf;
    }

    const response =
      method === "GET"
        ? await this.session.fetch(withCommonParams(url, bodyFields), { method: "GET", headers })
        : await this.session.fetch(url, {
            method: "POST",
            headers: { ...headers, "content-type": "application/x-www-form-urlencoded; charset=UTF-8" },
            body: new URLSearchParams(bodyFields).toString(),
          });

    this.lastToken = response.headers.get("x-tt-token") ?? undefined;
    this.captureTicketGuardServerData(response.headers.get("tt-ticket-guard-server-data"));
    if (this.lastToken && "sessionToken" in this.state) {
      this.state.sessionToken = this.lastToken;
    }

    if (response.status < 200 || response.status >= 300) {
      throw new SignupError(`HTTP ${response.status}`, { code: response.status, nextAction: "failed" });
    }
    let rawBytes = Buffer.from(await response.arrayBuffer());
    if (response.headers.get("content-encoding")?.toLowerCase() === "gzip") {
      rawBytes = Buffer.from(gunzipSync(rawBytes));
    }
    let result: unknown;
    try {
      result = JSON.parse(rawBytes.toString("utf8"));
    } catch (err) {
      throw new SignupError("invalid JSON response", { data: err, nextAction: "failed" });
    }
    if (typeof result !== "object" || result === null || Array.isArray(result)) {
      throw new SignupError("response root must be an object", { nextAction: "failed" });
    }
    const root = result as Record<string, unknown>;
    const data = typeof root.data === "object" && root.data !== null && !Array.isArray(root.data) ? (root.data as Record<string, unknown>) : {};
    const message = root.message;
    let code = root.error_code ?? root.code;
    if (code === undefined || code === null || code === 0 || code === "0") {
      code = data.error_code ?? data.code;
    }
    const statusCode = root.status_code;
    if (
      statusCode !== undefined &&
      statusCode !== null &&
      statusCode !== 0 &&
      statusCode !== "0" &&
      (code === undefined || code === null || code === 0 || code === "0")
    ) {
      throw new SignupError(String(root.status_msg ?? root.message ?? `aweme error ${statusCode}`), {
        code: statusCode,
        data: root,
        nextAction: "failed",
      });
    }
    const hasError =
      (message === "error" || message === "exception" || (code !== undefined && code !== null && code !== 0 && code !== "0")) &&
      !data.sms_code_key;
    if (hasError) {
      const challengeKeys = ["captcha", "recaptcha", "recaptcha_token", "shark_ticket", "verify_ticket", "verify_center_decision_conf"];
      const nextAction = challengeKeys.some((k) => k in data) ? "needs_challenge" : "failed";
      const desc =
        data.description ??
        root.description ??
        data.message ??
        (typeof message === "string" && message !== "error" && message !== "exception" ? message : undefined) ??
        `signup error ${String(code)}`;
      throw new SignupError(String(desc), { code, data: root.data, nextAction });
    }
    return root;
  }

  private static dataOf(result: Record<string, unknown>): Record<string, unknown> {
    return typeof result.data === "object" && result.data !== null && !Array.isArray(result.data)
      ? (result.data as Record<string, unknown>)
      : {};
  }

  private completeResult(result: Record<string, unknown>): void {
    if (!this.lastToken) {
      throw new SignupError("registration response is missing x-tt-token", { data: result });
    }
    const data = SignupClient.dataOf(result);
    if (Object.keys(data).length === 0) {
      throw new SignupError("registration response is missing user data", { data: result });
    }
    Object.assign(this.state, {
      status: "completed",
      nextAction: "completed",
      result,
      sessionToken: this.lastToken,
    });
  }

  async startEmail(email: string, codeType: number, options: { password?: string } = {}): Promise<SignupPublicState> {
    const check = await this.request("/passport/user/check_email_registered", {
      email: mixEncode(email),
      mix_mode: "1",
    });
    const checkData = SignupClient.dataOf(check);
    if (checkData.is_registered) {
      throw new SignupError("email is already registered", { code: "already_registered", data: checkData });
    }
    const sent = await this.request("/passport/email/send_code/", {
      email: mixEncode(email),
      type: mixEncode(String(codeType)),
      ...(options.password ? { password: mixEncode(options.password) } : {}),
      mix_mode: "1",
      fixed_mix_mode: "1",
    });
    const data = SignupClient.dataOf(sent);
    Object.assign(this.state, {
      status: "needs_otp",
      nextAction: "submit_otp",
      method: "email",
      email,
      codeType,
      ...(options.password ? { password: options.password } : {}),
      hasAccount: data.has_account,
      retryTime: data.retry_time ?? 30,
    });
    return this.publicState();
  }

  async startMobile(
    mobile: string,
    codeType: number,
    options: { autoRead?: number; checkRegister?: number; tickets?: Record<string, string> } = {},
  ): Promise<SignupPublicState> {
    const sent = await this.request("/passport/mobile/send_code/v1/", {
      mobile: mixEncode(mobile),
      type: mixEncode(String(codeType)),
      unbind_exist: mixEncode("0"),
      mix_mode: "1",
      check_register: String(options.checkRegister ?? 0),
      is6Digits: "1",
      auto_read: String(options.autoRead ?? 0),
      ...(options.tickets ?? {}),
    });
    const data = SignupClient.dataOf(sent);
    if (data.has_account) {
      throw new SignupError("mobile already has an account", { code: "already_registered", data });
    }
    Object.assign(this.state, {
      status: "needs_otp",
      nextAction: "submit_otp",
      method: "mobile",
      mobile,
      codeType,
      hasAccount: data.has_account,
      retryTime: data.retry_time ?? 30,
      ...(typeof data.mobile_ticket === "string" ? { mobileTicket: data.mobile_ticket } : {}),
    });
    return this.publicState();
  }

  async submitOtp(code: string): Promise<SignupPublicState> {
    if (this.state.status !== "needs_otp") {
      throw new SignupError("OTP is not expected in this state", { nextAction: String(this.state.nextAction ?? "failed") });
    }
    let result: Record<string, unknown>;
    if (this.state.method === "email") {
      result = await this.request("/passport/email/check_code/", {
        email: mixEncode(String(this.state.email)),
        code: mixEncode(code),
        type: mixEncode(String(this.state.codeType)),
        mix_mode: "1",
        fixed_mix_mode: "1",
      });
    } else if (this.state.method === "mobile") {
      result = await this.request("/passport/mobile/check_code/", {
        mobile: mixEncode(String(this.state.mobile)),
        code: mixEncode(code),
        type: mixEncode(String(this.state.codeType)),
        mix_mode: "1",
        fixed_mix_mode: "1",
      });
    } else {
      throw new SignupError("signup method is not initialized");
    }
    const ticket = SignupClient.dataOf(result).ticket;
    if (typeof ticket !== "string" || !ticket) {
      throw new SignupError("check_code response is missing data.ticket", { data: result });
    }
    Object.assign(this.state, {
      status: "verified",
      nextAction: "complete",
      ticket,
      otp: code,
    });
    return this.publicState();
  }

  async completeEmail(options: { password?: string; recaptchaToken?: string } = {}): Promise<SignupPublicState> {
    if (this.state.status !== "verified" || this.state.method !== "email") {
      throw new SignupError("email OTP verification is required first");
    }
    const chosenPassword = options.password ?? (typeof this.state.password === "string" ? this.state.password : undefined);
    if (!chosenPassword) {
      throw new SignupError("password is required to complete email signup", { nextAction: "submit_password" });
    }
    const result = await this.request("/passport/email/register/v2/", {
      email: mixEncode(String(this.state.email)),
      code: mixEncode(String(this.state.otp)),
      password: mixEncode(chosenPassword),
      mix_mode: "1",
      fixed_mix_mode: "1",
      ...(options.recaptchaToken ? { recaptcha_token: options.recaptchaToken } : {}),
    });
    this.state.password = chosenPassword;
    this.completeResult(result);
    return this.publicState();
  }

  async completeMobile(options: { captcha?: string; notLoginTicket?: string; birthday?: string } = {}): Promise<SignupPublicState> {
    if (this.state.status !== "verified" || this.state.method !== "mobile") {
      throw new SignupError("mobile OTP verification is required first");
    }
    const ticket = options.notLoginTicket ?? (typeof this.state.ticket === "string" ? this.state.ticket : undefined);
    let result = await this.request("/passport/mobile/sms_login/", {
      mobile: mixEncode(String(this.state.mobile)),
      code: mixEncode(String(this.state.otp)),
      mix_mode: "1",
      ...(options.captcha ? { captcha: options.captcha } : {}),
      ...(ticket ? { not_login_ticket: ticket } : {}),
      ...(options.birthday ? { birthday: options.birthday } : {}),
    });
    const smsCodeKey = SignupClient.dataOf(result).sms_code_key;
    if (smsCodeKey) {
      result = await this.request("/passport/mobile/sms_login_continue/", {
        mobile: mixEncode(String(this.state.mobile)),
        sms_code_key: mixEncode(String(smsCodeKey)),
        mix_mode: "1",
      });
    }
    this.completeResult(result);
    return this.publicState();
  }

  async completeMobileLoginOnly(
    code?: string,
    options: { birthday?: string; carrierRegion?: string; verifyReusedMobile?: boolean; captcha?: string } = {},
  ): Promise<SignupPublicState> {
    const otp = code ?? (typeof this.state.otp === "string" ? this.state.otp : undefined);
    if (this.state.method !== "mobile" || (this.state.status !== "needs_otp" && this.state.status !== "verified") || !otp) {
      throw new SignupError("mobile OTP verification is required first");
    }
    this.state.otp = otp;
    let result = await this.request("/passport/mobile/sms_login_only/", {
      mobile: mixEncode(String(this.state.mobile)),
      ...(options.captcha ? { captcha: options.captcha } : {}),
      code: mixEncode(otp),
      mix_mode: "1",
      enable_account_selection: "1",
      scene: "0",
      ...(options.verifyReusedMobile !== false ? { verify_reused_mobile: "true" } : {}),
    });
    const smsCodeKey = SignupClient.dataOf(result).sms_code_key;
    if (smsCodeKey) {
      this.state.smsCodeKey = String(smsCodeKey);
      result = await this.request("/passport/mobile/sms_login_continue/", {
        mobile: mixEncode(String(this.state.mobile)),
        sms_code_key: mixEncode(String(smsCodeKey)),
        mix_mode: "1",
        ...(options.birthday ? { birthday: options.birthday } : {}),
        ...(options.carrierRegion ? { carrier_region: options.carrierRegion } : {}),
      });
    }
    this.completeResult(result);
    return this.publicState();
  }

  async checkLoginName(loginName: string): Promise<SignupPublicState> {
    const result = await this.request("/passport/login_name/check/", { login_name: loginName });
    const data = SignupClient.dataOf(result);
    Object.assign(this.state, {
      loginName: typeof data.login_name === "string" ? data.login_name : loginName,
      loginNameAvailable: true,
      ...(Array.isArray(data.recommended_login_names) ? { recommendedLoginNames: data.recommended_login_names.map(String) } : {}),
    });
    return this.publicState();
  }

  async registerLoginName(
    loginName: string,
    options: { isFromNickname?: boolean; aid?: string | number } = {},
  ): Promise<SignupPublicState> {
    const aid = options.aid ?? this.queryParams.aid ?? "1233";
    const result = await this.request("/passport/login_name/register/", {
      aid: String(aid),
      login_name: loginName,
      is_from_nickname: options.isFromNickname ? "true" : "false",
    });
    const data = SignupClient.dataOf(result);
    const finalName = typeof data.login_name === "string" && data.login_name ? data.login_name : loginName;
    Object.assign(this.state, { loginName: finalName, uniqueId: finalName });
    return this.publicState();
  }

  async updateLoginName(loginName: string): Promise<SignupPublicState> {
    const result = await this.request("/passport/login_name/update/", { login_name: loginName });
    const data = SignupClient.dataOf(result);
    const finalName = typeof data.login_name === "string" && data.login_name ? data.login_name : loginName;
    Object.assign(this.state, { loginName: finalName, uniqueId: finalName });
    return this.publicState();
  }

  async commitUserProfile(options: {
    nickname?: string;
    signature?: string;
    avatarUri?: string;
    uniqueId?: string;
    extraFields?: Record<string, string>;
  }): Promise<SignupPublicState> {
    const fields: Record<string, string> = { ...(options.extraFields ?? {}) };
    if (options.nickname !== undefined) fields.nickname = options.nickname;
    if (options.signature !== undefined) fields.signature = options.signature;
    if (options.avatarUri !== undefined) fields.avatar_uri = options.avatarUri;
    if (options.uniqueId !== undefined) fields.unique_id = options.uniqueId;
    if (Object.keys(fields).length === 0) {
      throw new SignupError("at least one profile field is required");
    }
    const result = await this.request("/aweme/v1/commit/user/", fields);
    const user = typeof result.user === "object" && result.user !== null ? (result.user as Record<string, unknown>) : {};
    if (options.nickname !== undefined || typeof user.nickname === "string") {
      this.state.nickname = typeof user.nickname === "string" ? user.nickname : options.nickname;
    }
    if (options.signature !== undefined || typeof user.signature === "string") {
      this.state.signature = typeof user.signature === "string" ? user.signature : options.signature;
    }
    if (options.avatarUri !== undefined) {
      this.state.avatarUri = options.avatarUri;
    }
    if (options.uniqueId !== undefined || typeof user.unique_id === "string") {
      this.state.uniqueId = typeof user.unique_id === "string" ? user.unique_id : options.uniqueId;
    }
    return this.publicState();
  }

  async tokenBeat(options: { scene?: string; firstBeat?: boolean } = {}): Promise<SignupPublicState> {
    const scene = options.scene ?? "boot";
    await this.request(
      "/passport/token/beat/v2/",
      {
        scene,
        first_beat: options.firstBeat !== false ? "true" : "false",
      },
      "GET",
    );
    this.state.tokenBeatScene = scene;
    return this.publicState();
  }

  async getAccountInfo(options: { scene?: string; deviceMigrateTime?: number; getInfoType?: number } = {}): Promise<SignupPublicState> {
    const fields: Record<string, string> = {
      scene: options.scene ?? "login",
      device_migrate_time: String(options.deviceMigrateTime ?? 0),
    };
    if (options.getInfoType !== undefined || options.getInfoType === undefined) {
      fields.get_info_type = String(options.getInfoType ?? 1);
    }
    const result = await this.request("/passport/account/info/v2/", fields);
    const data = SignupClient.dataOf(result);
    const uid =
      typeof data.user_id_str === "string"
        ? data.user_id_str
        : data.user_id !== undefined && data.user_id !== null
          ? String(data.user_id)
          : undefined;
    const screenName = typeof data.screen_name === "string" ? data.screen_name : typeof data.username === "string" ? data.username : undefined;
    if (uid) this.state.accountUserId = uid;
    if (screenName) this.state.screenName = screenName;
    return this.publicState();
  }
}

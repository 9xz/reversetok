import {
  createSession,
  fetch as wreqFetch,
  Headers as WreqHeaders,
  type CreateSessionOptions,
  type HeadersInit,
  type RequestInit as WreqRequestInit,
  type Response as WreqResponse,
  type Session,
} from "wreq-js";

import { signRequest } from "./crypto";
import type { Persona, SignInput } from "./types";

export type ReplayOptions = Pick<SignInput, "nowSeconds" | "nonce" | "rnd4Hex" | "ladonRandom4Hex" | "headerHex" | "trailerHex" | "key4Hex">;
export type WreqClientDefaults = Omit<WreqRequestInit, "method" | "headers" | "body">;
export type WreqFetchOptions = Omit<WreqRequestInit, "method" | "headers" | "body"> & {
  method?: string;
  headers?: Record<string, string>;
  body?: string | ArrayBuffer | ArrayBufferView | URLSearchParams | Buffer | null;
  bodyBase64?: string;
  replay?: ReplayOptions;
};
export type WreqSessionFetchOptions = Omit<
  WreqFetchOptions,
  "transport" | "browser" | "os" | "emulation" | "proxy" | "cookieMode" | "session" | "sessionId" | "insecure" | "trustStore"
>;
export type WreqSessionOptions = CreateSessionOptions;
export interface WreqSessionCookie {
  name: string;
  value: string;
  domain?: string;
  path?: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: "lax" | "strict" | "none";
  expiresAtMs?: number;
}

function headersRecord(init: HeadersInit | undefined): Record<string, string> {
  return init === undefined ? {} : new WreqHeaders(init).toObject();
}

function mergeHeaders(...sources: (HeadersInit | undefined)[]): Record<string, string> {
  const merged = new WreqHeaders();
  for (const source of sources) {
    if (source === undefined) continue;
    for (const [name, value] of new WreqHeaders(source)) merged.set(name, value);
  }
  return merged.toObject();
}

function bodyBytes(options: Pick<WreqFetchOptions, "body" | "bodyBase64">): Buffer {
  if (options.bodyBase64 !== undefined) return Buffer.from(options.bodyBase64, "base64");
  const body = options.body;
  if (body === undefined || body === null) return Buffer.alloc(0);
  if (typeof body === "string") return Buffer.from(body, "utf8");
  if (body instanceof URLSearchParams) return Buffer.from(body.toString(), "utf8");
  if (body instanceof ArrayBuffer) return Buffer.from(body);
  if (ArrayBuffer.isView(body)) return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  throw new TypeError("wreq body must be a string, Buffer, ArrayBuffer, ArrayBufferView, URLSearchParams, or bodyBase64");
}

function prepareRequest(
  persona: Persona,
  defaults: WreqClientDefaults,
  url: string,
  options: WreqFetchOptions,
): WreqRequestInit {
  const {
    replay,
    bodyBase64: _bodyBase64,
    body: _body,
    headers: _headers,
    method: _method,
    ...requestOptions
  } = options;
  const body = bodyBytes(options);
  const inputHeaders = headersRecord(options.headers);
  const signed = signRequest({
    persona,
    method: options.method ?? "GET",
    url,
    headers: inputHeaders,
    body,
    ...replay,
  });
  return {
    ...defaults,
    ...requestOptions,
    method: options.method ?? "GET",
    headers: mergeHeaders(inputHeaders, signed.headers),
    body: body.length === 0 ? null : body,
  };
}

export class WreqClient {
  constructor(
    private readonly persona: Persona,
    private readonly defaults: WreqClientDefaults = {},
  ) {}

  async fetch(url: string, options: WreqFetchOptions = {}): Promise<WreqResponse> {
    return wreqFetch(url, prepareRequest(this.persona, this.defaults, url, options));
  }
}

export class WreqSession {
  private constructor(
    private persona: Persona,
    private readonly session: Session,
    private readonly defaultHeaders: Record<string, string>,
  ) {}

  private static async create(persona: Persona, options: WreqSessionOptions): Promise<WreqSession> {
    const { defaultHeaders, ...sessionOptions } = options;
    const session = await createSession(sessionOptions);
    return new WreqSession(persona, session, headersRecord(defaultHeaders));
  }

  static async open(persona: Persona, options: WreqSessionOptions = {}): Promise<WreqSession> {
    return WreqSession.create(persona, options);
  }

  get id(): string {
    return this.session.id;
  }

  get closed(): boolean {
    return this.session.closed;
  }


  getPersona(): Persona {
    return { ...this.persona };
  }

  updatePersona(updates: Partial<Persona>): Persona {
    this.persona = { ...this.persona, ...updates };
    return this.getPersona();
  }
  async fetch(url: string, options: WreqSessionFetchOptions = {}): Promise<WreqResponse> {
    const headers = mergeHeaders(this.defaultHeaders, options.headers);
    return this.session.fetch(url, prepareRequest(this.persona, {}, url, { ...options, headers }));
  }

  getCookies(url: string | URL): Record<string, string> {
    return this.session.getCookies(url);
  }

  getAllCookies(): WreqSessionCookie[] {
    return this.session.getAllCookies();
  }

  setCookie(name: string, value: string, url: string | URL): void {
    this.session.setCookie(name, value, url);
  }

  async clearCookies(): Promise<void> {
    await this.session.clearCookies();
  }

  async close(): Promise<void> {
    await this.session.close();
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }
}

export function createWreqClient(persona: Persona, defaults: WreqClientDefaults = {}): WreqClient {
  return new WreqClient(persona, defaults);
}

export async function createWreqSession(persona: Persona, options: WreqSessionOptions = {}): Promise<WreqSession> {
  return WreqSession.open(persona, options);
}

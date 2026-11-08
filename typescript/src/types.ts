export interface DynTail {
  algorithm: number;
  outputHex: string;
}

export interface Persona {
  deviceId: string;
  installId: string;
  appId?: string;
  licenseId?: number;
  sdkVersion?: string;
  sdkVersionCode?: number;
  appVersion?: string;
  versionCode?: string;
  model?: string;
  device?: string;
  build?: string;
  release?: string;
  securityPatch?: string;
  fingerprint?: string;
  channel?: string;
  resolution?: string;
  dpi?: number;
  allowEmptyIdentity?: boolean;
  deviceToken?: string;
  dynSeed?: string;
  dynVersion?: number;
  seedState?: number;
  sessionBlobHex?: string;
  rsk2Ms?: number;
  envSalt32?: number;
  f23Field2?: number;
  f23Field4?: number;
  f23Field5?: number;
  f26Tail?: DynTail[];
  f34?: string;
  f35?: string;
  f36?: string;
}

export interface SignInput {
  persona: Persona;
  method?: string;
  url: string;
  headers?: Record<string, string>;
  body?: Uint8Array | string;
  bodyBase64?: string;
  nowSeconds?: number;
  nonce?: number;
  rnd4Hex?: string;
  ladonRandom4Hex?: string;
  headerHex?: string;
  trailerHex?: string;
  key4Hex?: string;
}

export interface SignOutput {
  headers: Record<string, string>;
  method: string;
  url: string;
  bodyBase64: string;
}

export interface DynamicFields {
  dynSeed: string;
  dynVersion: number;
  seedState: number;
  nonce: number;
  nowSeconds: number;
  f26Tail: DynTail[];
}

export interface DynamicInput {
  argus: string;
  url: string;
  body?: Uint8Array | string;
  bodyBase64?: string;
}

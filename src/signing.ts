// The checking agent's identity (Poppy 1.0 §5.2). Per run: a fresh ES256 delegated key,
// vouched for by the root key in a delegation JWT. Per request: a Session JWT signed with the
// delegated key, naming the Session (sid), the User ID (sub), the method and the URL.
//
// `forge` lets the refusal checks (stage E) break exactly one rule at a time.

import { SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK, decodeJwt, decodeProtectedHeader, type JWK } from 'jose';
import { randomBytes, randomUUID } from 'node:crypto';
import { VERSIONS } from './config.js';

type KeyLike = CryptoKey | Uint8Array;

export interface RootKey {
  kid: string;
  alg: 'ES256' | 'PS384';
  key: KeyLike;
}

export type RootKeys = { es256: RootKey; ps384: RootKey };

/** Root keys from two private JWKs as JSON strings (ES256 and PS384). */
export async function loadRootKeys(es256Json: string, ps384Json: string): Promise<RootKeys> {
  return { es256: await importRoot(JSON.parse(es256Json), 'ES256'), ps384: await importRoot(JSON.parse(ps384Json), 'PS384') };
}

/** Root keys from POPPY_AGENT_ES256_JWK and POPPY_AGENT_PS384_JWK, or null if not set or invalid. */
export async function rootKeysFromEnv(env: Record<string, string | undefined> = process.env): Promise<RootKeys | null> {
  const es = env.POPPY_AGENT_ES256_JWK?.trim();
  const ps = env.POPPY_AGENT_PS384_JWK?.trim();
  if (!es || !ps) return null;
  try {
    return await loadRootKeys(es, ps);
  } catch {
    return null;
  }
}

export async function importRoot(jwk: JWK, alg: 'ES256' | 'PS384'): Promise<RootKey> {
  if (!jwk.kid) throw new Error('root key has no kid');
  return { kid: jwk.kid, alg, key: (await importJWK(jwk, alg)) as KeyLike };
}

export interface Forge {
  /** Leave out Poppy-Version, or send this value. */
  version?: string | null;
  aud?: string;
  htu?: string;
  htm?: string;
  iatOffset?: number;
  kid?: string;
  /** Sign the Session JWT with a key other than cnf.jwk (kid still names cnf.jwk). */
  wrongSessionKey?: boolean;
  /** Sign the delegation with a key that isn't in our jwks_uri (kid still names a real one). */
  unknownRootKey?: boolean;
  /** Delegation lifetime in seconds (exp − iat). */
  delegationLifetime?: number;
  /** Delegation iat offset in seconds (negative = in the past). */
  delegationIatOffset?: number;
  extraClaims?: Record<string, unknown>;
  /** iss in both the delegation and the Session JWT. */
  iss?: string;
  /** Sign the delegation with the PS384 root key. */
  ps384?: boolean;
  /** Send this as the raw Poppy-Session header value. */
  raw?: string;
}

const now = () => Math.floor(Date.now() / 1000);

export interface SignedHeaders {
  headers: Record<string, string>;
  decoded?: { header: Record<string, unknown>; claims: Record<string, unknown>; delegation?: Record<string, unknown> };
}

export class Agent {
  readonly sid: string;
  readonly sub: string;
  version: string;
  readonly clientId: string;
  #roots: RootKeys;
  #aud: string;
  #del?: { publicJwk: JWK; privateKey: KeyLike; kid: string };
  #dlg = new Map<string, string>();

  constructor(o: { roots: RootKeys; clientId: string; aud: string; version?: string; sid?: string; sub?: string }) {
    this.clientId = o.clientId;
    this.#roots = o.roots;
    this.#aud = o.aud;
    this.version = o.version ?? VERSIONS[0];
    this.sid = o.sid ?? randomBytes(16).toString('base64url');
    this.sub = o.sub ?? `chk_${randomBytes(4).toString('hex')}`;
  }

  /** The company identifier every Session JWT names in aud (§3.2). */
  set audience(aud: string) {
    this.#aud = aud;
  }
  get audience() {
    return this.#aud;
  }

  async #delegated() {
    if (!this.#del) {
      const pair = await generateKeyPair('ES256', { extractable: true });
      const publicJwk = await exportJWK(pair.publicKey);
      this.#del = { publicJwk, privateKey: pair.privateKey as KeyLike, kid: await calculateJwkThumbprint(publicJwk) };
    }
    return this.#del;
  }

  /** A delegation JWT for our delegated key. Cached for the normal case. */
  async delegation(f: Forge = {}): Promise<string> {
    const d = await this.#delegated();
    const normal = !f.unknownRootKey && f.delegationLifetime === undefined && f.delegationIatOffset === undefined && !f.iss && !f.ps384;
    if (normal && this.#dlg.has('normal')) return this.#dlg.get('normal')!;
    const root = f.ps384 ? this.#roots.ps384 : this.#roots.es256;
    let signingKey = root.key;
    if (f.unknownRootKey) signingKey = (await generateKeyPair('ES256')).privateKey as KeyLike;
    const iat = now() + (f.delegationIatOffset ?? 0);
    const jwt = await new SignJWT({ cnf: { jwk: d.publicJwk }, jti: randomUUID() })
      .setProtectedHeader({ alg: root.alg, typ: 'poppy-delegation+jwt', kid: root.kid })
      .setIssuer(f.iss ?? this.clientId)
      .setIssuedAt(iat)
      .setExpirationTime(iat + (f.delegationLifetime ?? 900))
      .sign(signingKey);
    if (normal) this.#dlg.set('normal', jwt);
    return jwt;
  }

  /** Session headers for one request. */
  async sign(method: string, url: string, f: Forge = {}): Promise<SignedHeaders> {
    const headers: Record<string, string> = {};
    if (f.version !== null) headers['poppy-version'] = f.version ?? this.version;
    if (f.raw !== undefined) {
      headers['poppy-session'] = f.raw;
      return { headers, decoded: { header: { note: 'not a JWT' }, claims: { raw: f.raw } } };
    }
    const d = await this.#delegated();
    const dlg = await this.delegation(f);
    let key = d.privateKey;
    if (f.wrongSessionKey) key = (await generateKeyPair('ES256')).privateKey as KeyLike;
    const u = new URL(url);
    const htu = f.htu ?? `${u.origin}${u.pathname}`;
    const claims: Record<string, unknown> = {
      sid: this.sid,
      sub: this.sub,
      htm: f.htm ?? method.toUpperCase(),
      htu,
      jti: randomUUID(),
      ...(f.extraClaims ?? {}),
    };
    const jwt = await new SignJWT(claims)
      .setProtectedHeader({ alg: 'ES256', typ: 'poppy-session+jwt', kid: f.kid ?? d.kid, poppy_dlg: dlg })
      .setIssuer(f.iss ?? this.clientId)
      .setAudience(f.aud ?? this.#aud)
      .setIssuedAt(now() + (f.iatOffset ?? 0))
      .sign(key);
    headers['poppy-session'] = jwt;
    return { headers, decoded: decodeSession(jwt) };
  }

  /** A signer for Fetcher.request. */
  signer(f: Forge = {}) {
    return (method: string, url: string) => this.sign(method, url, f);
  }
}

/** Decodes a Session JWT for display: header (with the delegation summarised) and claims. */
export function decodeSession(jwt: string): SignedHeaders['decoded'] {
  try {
    const header = decodeProtectedHeader(jwt) as Record<string, unknown>;
    const claims = decodeJwt(jwt) as Record<string, unknown>;
    let delegation: Record<string, unknown> | undefined;
    if (typeof header.poppy_dlg === 'string') {
      const dh = decodeProtectedHeader(header.poppy_dlg) as Record<string, unknown>;
      const dc = decodeJwt(header.poppy_dlg) as Record<string, unknown>;
      delegation = { alg: dh.alg, kid: dh.kid, typ: dh.typ, iss: dc.iss, iat: dc.iat, exp: dc.exp };
    }
    return { header: { ...header, poppy_dlg: '‹delegation›' }, claims, delegation };
  } catch {
    return undefined;
  }
}

// Outbound HTTP for the readiness checks and real tasks. Every request a stranger can point
// at any domain goes through here, so this file is the SSRF boundary:
//   - HTTPS on port 443 only;
//   - every host is resolved, and refused if ANY address is private, loopback, link-local,
//     CGNAT, ULA, multicast, unspecified or an IPv4-mapped/NAT64 form of those. The same check
//     runs again at connect time (undici's lookup hook), so DNS rebinding can't slip past;
//   - redirects are never followed automatically. Discovery may follow HTTPS hops; anything
//     carrying a Session JWT follows at most one same-host HTTPS hop and is re-signed for it;
//   - per-request timeout, response body cap, request count cap and a run deadline.

import { lookup as dnsLookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { Agent, fetch as undiciFetch } from 'undici';
import { DEFAULT_USER_AGENT, LIMITS } from './config.js';

export type LookupFn = (host: string) => Promise<string[]>;
export type FetchFn = (url: string, init: any) => Promise<Response>;

export class NetError extends Error {
  constructor(
    public code: 'refused_private' | 'refused_url' | 'timeout' | 'budget' | 'request_cap' | 'network' | 'blocked',
    message: string,
  ) {
    super(message);
  }
}

// ---------- Address checks ----------

function v4ToInt(ip: string): number {
  return ip.split('.').reduce((n, o) => (n << 8) + Number(o), 0) >>> 0;
}

const V4_BLOCKED: [string, number][] = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
];

function blockedV4(ip: string): boolean {
  const n = v4ToInt(ip);
  return V4_BLOCKED.some(([base, bits]) => {
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (n & mask) === (v4ToInt(base) & mask);
  });
}

/** Expands an IPv6 address to 8 groups of numbers. */
function v6Groups(ip: string): number[] | null {
  let s = ip.toLowerCase().split('%')[0];
  // Trailing dotted IPv4 (::ffff:1.2.3.4)
  const m = s.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (m) {
    const n = v4ToInt(m[2]);
    s = `${m[1]}${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  const [head, tail] = s.split('::');
  const h = head ? head.split(':') : [];
  const t = tail !== undefined ? (tail ? tail.split(':') : []) : [];
  if (s.includes('::')) {
    const fill = 8 - h.length - t.length;
    if (fill < 0) return null;
    return [...h, ...Array(fill).fill('0'), ...t].map((g) => parseInt(g, 16));
  }
  return h.length === 8 ? h.map((g) => parseInt(g, 16)) : null;
}

/** True if the address must never be contacted. */
export function isBlockedAddress(ip: string): boolean {
  const kind = isIP(ip);
  if (kind === 4) return blockedV4(ip);
  if (kind !== 6) return true;
  const g = v6Groups(ip);
  if (!g || g.some((x) => Number.isNaN(x))) return true;
  const embedded = () => `${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`;
  if (g.every((x) => x === 0)) return true; // ::
  if (g.slice(0, 7).every((x) => x === 0) && g[7] === 1) return true; // ::1
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return blockedV4(embedded()); // ::ffff:a.b.c.d
  if (g.slice(0, 6).every((x) => x === 0)) return true; // ::a.b.c.d (deprecated compatible)
  if (g[0] === 0x64 && g[1] === 0xff9b) return blockedV4(embedded()); // NAT64
  if ((g[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 ULA
  if ((g[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((g[0] & 0xff00) === 0xff00) return true; // multicast
  if (g[0] === 0x2001 && g[1] === 0x0db8) return true; // documentation
  return false;
}

export const systemLookup: LookupFn = async (host) => {
  const res = await dnsLookup(host, { all: true, verbatim: true });
  return res.map((r) => r.address);
};

/** Resolves a host and throws unless every address is public. */
export async function assertPublicHost(host: string, lookup: LookupFn = systemLookup): Promise<string[]> {
  const bare = host.replace(/^\[|\]$/g, '');
  if (isIP(bare)) {
    if (isBlockedAddress(bare)) throw new NetError('refused_private', `Refused: private address (${host}).`);
    return [bare];
  }
  if (/(^|\.)(localhost|local|internal|localdomain|home\.arpa)$/i.test(bare)) {
    throw new NetError('refused_private', `Refused: private address (${host}).`);
  }
  let addrs: string[];
  try {
    addrs = await lookup(bare);
  } catch {
    throw new NetError('network', `${host} doesn't resolve.`);
  }
  if (addrs.length === 0) throw new NetError('network', `${host} doesn't resolve.`);
  if (addrs.some(isBlockedAddress)) throw new NetError('refused_private', `Refused: private address (${host} resolves to a private network).`);
  return addrs;
}

/** Checks a URL is one we may call: HTTPS, port 443, no credentials. Returns the parsed URL. */
export function checkUrl(raw: string): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new NetError('refused_url', `Not a valid URL: ${raw.slice(0, 200)}`);
  }
  if (u.protocol !== 'https:') throw new NetError('refused_url', `Refused: not HTTPS (${u.origin}).`);
  if (u.port && u.port !== '443') throw new NetError('refused_url', `Refused: only port 443 is checked (${u.host}).`);
  if (u.username || u.password) throw new NetError('refused_url', 'Refused: URL contains credentials.');
  return u;
}

// The real fetch: undici with a connect-time lookup that applies the same address rules.
let agent: Agent | undefined;
function safeAgent(): Agent {
  agent ??= new Agent({
    connect: {
      lookup: (hostname: string, options: any, cb: any) => {
        systemLookup(hostname)
          .then((addrs) => {
            if (addrs.length === 0 || addrs.some(isBlockedAddress)) return cb(new Error('blocked address'));
            const family = isIP(addrs[0]);
            if (options?.all) cb(null, addrs.map((a) => ({ address: a, family: isIP(a) })));
            else cb(null, addrs[0], family);
          })
          .catch((e) => cb(e));
      },
    },
  });
  return agent;
}
const defaultFetch: FetchFn = (url, init) => undiciFetch(url, { ...init, dispatcher: safeAgent() }) as unknown as Promise<Response>;

// ---------- The fetcher ----------

export interface LogEntry {
  n: number;
  method: string;
  url: string;
  status: number | null;
  snippet: string;
  note?: string;
  /** Decoded Session JWT header and claims (never the raw token). */
  session?: { header: Record<string, unknown>; claims: Record<string, unknown>; delegation?: Record<string, unknown> };
  error?: string;
}

export interface FetchResult {
  url: string;
  status: number;
  headers: Headers;
  text: string;
  truncated: boolean;
  /** Set when a redirect wasn't followed. */
  redirectRefused?: { location: string; reason: string };
}

export interface RequestOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  /** Builds the Session headers for a method and URL (re-run on a same-host redirect). */
  sign?: (method: string, url: string) => Promise<{ headers: Record<string, string>; decoded?: LogEntry['session'] }>;
  /** Discovery: follow HTTPS redirects (up to 5 hops), each one checked. Never with `sign`. */
  followRedirects?: boolean;
  note?: string;
  /** Per-request timeout override. */
  timeoutMs?: number;
}

export interface FetcherOptions {
  fetchImpl?: FetchFn;
  lookup?: LookupFn;
  maxRequests?: number;
  deadline?: number;
  onLog?: (e: LogEntry) => void;
  /** Hosts that asked not to be checked. */
  blocklist?: string[];
  userAgent?: string;
}

export class Fetcher {
  count = 0;
  readonly hops: string[] = [];
  #fetch: FetchFn;
  #lookup: LookupFn;
  #max: number;
  #deadline: number;
  #onLog: (e: LogEntry) => void;
  #blocklist: string[];
  #userAgent: string;

  constructor(o: FetcherOptions = {}) {
    this.#fetch = o.fetchImpl ?? defaultFetch;
    this.#lookup = o.lookup ?? systemLookup;
    this.#max = o.maxRequests ?? LIMITS.maxRequests;
    this.#deadline = o.deadline ?? Date.now() + LIMITS.runMs;
    this.#onLog = o.onLog ?? (() => {});
    this.#blocklist = (o.blocklist ?? []).map((h) => h.toLowerCase());
    this.#userAgent = o.userAgent ?? DEFAULT_USER_AGENT;
  }

  get remainingMs() {
    return this.#deadline - Date.now();
  }

  get remainingRequests() {
    return this.#max - this.count;
  }

  /** Checks a URL and its host without sending anything. */
  async vet(raw: string): Promise<URL> {
    const u = checkUrl(raw);
    const host = u.hostname.toLowerCase();
    if (this.#blocklist.some((b) => host === b || host.endsWith(`.${b}`))) {
      throw new NetError('blocked', `${host} has asked not to be checked.`);
    }
    await assertPublicHost(u.hostname, this.#lookup);
    return u;
  }

  async request(raw: string, o: RequestOptions = {}): Promise<FetchResult> {
    const method = (o.method ?? 'GET').toUpperCase();
    let url = raw;
    let sameHostHopUsed = false;
    for (let hop = 0; ; hop++) {
      const u = await this.vet(url);
      url = u.toString();
      if (this.count >= this.#max) throw new NetError('request_cap', 'Request limit for this run reached.');
      const left = this.remainingMs;
      if (left <= 0) throw new NetError('budget', 'Time budget ran out.');
      this.count++;
      const n = this.count;

      const headers: Record<string, string> = { 'user-agent': this.#userAgent, ...(o.headers ?? {}) };
      let decoded: LogEntry['session'];
      if (o.sign) {
        const s = await o.sign(method, url);
        Object.assign(headers, s.headers);
        decoded = s.decoded;
      }

      let res: Response;
      try {
        res = await this.#fetch(url, {
          method,
          headers,
          body: o.body,
          redirect: 'manual',
          signal: AbortSignal.timeout(Math.min(o.timeoutMs ?? LIMITS.requestMs, left)),
        });
      } catch (err: any) {
        const timeout = err?.name === 'TimeoutError' || err?.name === 'AbortError';
        const msg = timeout ? 'Timed out.' : String(err?.cause?.message ?? err?.message ?? 'Network error').includes('blocked address') ? 'Refused: private address.' : 'Network error.';
        this.#onLog({ n, method, url, status: null, snippet: '', note: o.note, session: decoded, error: msg });
        throw new NetError(timeout ? 'timeout' : msg.startsWith('Refused') ? 'refused_private' : 'network', msg);
      }

      const { text, truncated } = await readCapped(res);
      this.#onLog({ n, method, url, status: res.status, snippet: text.slice(0, 300), note: o.note, session: decoded });
      this.hops.push(url);

      if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
        const loc = new URL(res.headers.get('location')!, url);
        const result = { url, status: res.status, headers: res.headers, text, truncated };
        if (o.followRedirects && !o.sign) {
          if (hop >= 5) return { ...result, redirectRefused: { location: loc.toString(), reason: 'Too many redirects.' } };
          if (loc.protocol !== 'https:') return { ...result, redirectRefused: { location: loc.toString(), reason: 'Redirect to a non-HTTPS URL.' } };
          url = loc.toString();
          continue;
        }
        if (o.sign && !sameHostHopUsed && loc.protocol === 'https:' && loc.host === u.host) {
          sameHostHopUsed = true;
          url = loc.toString();
          continue;
        }
        return {
          ...result,
          redirectRefused: {
            location: loc.toString(),
            reason: o.sign ? 'Redirected to another host or twice. Session JWTs are never sent across a redirect (§3).' : 'Redirect not followed.',
          },
        };
      }
      return { url, status: res.status, headers: res.headers, text, truncated };
    }
  }
}

async function readCapped(res: Response): Promise<{ text: string; truncated: boolean }> {
  if (!res.body) return { text: '', truncated: false };
  const reader = (res.body as ReadableStream<Uint8Array>).getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let truncated = false;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (size + value.byteLength > LIMITS.maxBodyBytes) {
        chunks.push(value.subarray(0, LIMITS.maxBodyBytes - size));
        truncated = true;
        await reader.cancel().catch(() => {});
        break;
      }
      chunks.push(value);
      size += value.byteLength;
    }
  } catch {
    truncated = true;
  }
  const buf = new Uint8Array(chunks.reduce((n, c) => n + c.byteLength, 0));
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.byteLength;
  }
  return { text: new TextDecoder().decode(buf), truncated };
}

/** Parses JSON, or returns undefined. */
export function parseJson(text: string): any {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/** Normalises what a visitor typed into a bare lowercase host, or null. */
export function normaliseDomain(input: unknown): string | null {
  if (typeof input !== 'string') return null;
  let s = input.trim().toLowerCase();
  if (!s || s.length > 253) return null;
  if (!/^https?:\/\//.test(s)) s = `https://${s}`;
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
  if (u.port && u.port !== '443') return null;
  if (u.username || u.password) return null;
  const host = u.hostname.replace(/\.$/, '');
  if (!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/.test(host)) return null;
  return host;
}

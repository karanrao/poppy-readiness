// Opting a domain in to real tasks. Real tasks create real data on the company's site, so they
// only run where the domain's owner has said yes: a list the operator passes in (their own sites),
// or a file at /.well-known/poppy-readiness.txt holding a code for this domain AND this operator's
// agent. Consent to one operator's agent isn't consent to another's; the file can hold several lines.
//
// The code isn't a secret: it's worked out from the domain and the agent's client_id, so it's the
// same every time and nothing is stored. What proves consent is being able to put the file there.

import { createHash } from 'node:crypto';
import type { Fetcher } from './net.js';

export const OPT_IN_PATH = '/.well-known/poppy-readiness.txt';

export function optInCode(domain: string, clientId: string): string {
  return 'prc_' + createHash('sha256').update(`poppy-readiness-opt-in:${domain.toLowerCase()}:${clientId}`).digest('hex').slice(0, 16);
}

export function optInFile(domain: string, clientId: string) {
  return { url: `https://${domain}${OPT_IN_PATH}`, contents: `real-tasks: ${optInCode(domain, clientId)}` };
}

export interface OptInOptions {
  clientId: string;
  /** Domains the operator may run real tasks on without a file: their own sites. */
  builtIn?: string[];
}

export type OptIn =
  | { ok: true; via: 'built-in' | 'file' }
  | { ok: false; code: 'not_found' | 'wrong_code' | 'unreachable'; message: string; file: { url: string; contents: string } };

/** Checks whether real tasks may run on this domain. Re-checked on every task request. */
export async function checkOptIn(fetcher: Fetcher, domain: string, o: OptInOptions): Promise<OptIn> {
  if ((o.builtIn ?? []).map((d) => d.toLowerCase()).includes(domain.toLowerCase())) return { ok: true, via: 'built-in' };
  const file = optInFile(domain, o.clientId);
  try {
    const r = await fetcher.request(file.url, { headers: { accept: 'text/plain' }, note: 'opt-in file' });
    if (r.status !== 200 || r.redirectRefused) {
      return {
        ok: false,
        code: 'not_found',
        message: r.redirectRefused
          ? `${OPT_IN_PATH} redirects. Serve it directly, with no redirect.`
          : `No file at ${OPT_IN_PATH} (${r.status}). It may take a minute to go live after you upload it.`,
        file,
      };
    }
    const want = optInCode(domain, o.clientId);
    const found = r.text
      .split(/\r?\n/)
      .map((l) => l.trim())
      .some((l) => l.replace(/\s+/g, ' ') === `real-tasks: ${want}`);
    if (!found) {
      return { ok: false, code: 'wrong_code', message: "Found the file, but its code doesn't match this domain. Copy the contents again: codes differ for every domain and subdomain.", file };
    }
    return { ok: true, via: 'file' };
  } catch (err: any) {
    return { ok: false, code: 'unreachable', message: err?.message ?? `Couldn't read ${OPT_IN_PATH}.`, file };
  }
}

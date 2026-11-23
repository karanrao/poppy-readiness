#!/usr/bin/env node
// poppy-readiness CLI.
//
//   poppy-readiness keys --client-id https://you.example/poppy-agent.json [--dir public]
//   poppy-readiness check example.com [--read-only] [--feedback] [--log] [--json] [--markdown]
//
// `check` needs your agent identity: POPPY_AGENT_CLIENT_ID plus POPPY_AGENT_ES256_JWK and
// POPPY_AGENT_PS384_JWK (from `keys`), or --env-file <path> holding those three lines.

import { parseArgs } from 'node:util';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { exportJWK, generateKeyPair } from 'jose';
import { runChecks } from './checks.js';
import { rootKeysFromEnv } from './signing.js';
import { normaliseDomain } from './net.js';
import { markdownReport, COMPANY_TYPE_LABEL } from './report.js';
import type { CheckEvent, DoneEvent } from './catalogue.js';

const HELP = `poppy-readiness: test a company's Personal Agent Protocol (Poppy) 1.0 setup.

Usage
  poppy-readiness check <domain> [options]   Run the readiness checks
  poppy-readiness keys --client-id <url>     Make your agent's keys and metadata

check options
  --read-only     Also call up to 3 read-only MCP tools or OpenAPI GET operations
  --feedback      Also send one test feedback report (writes to the company's database)
  --log           Print every request
  --json          Print events as NDJSON
  --markdown      Print the report as Markdown
  --env-file <f>  Read POPPY_AGENT_CLIENT_ID and the two keys from a file

keys options
  --client-id <url>  Where you'll host the agent's client metadata (HTTPS, no redirect)
  --dir <path>       Where to write agent.json and jwks.json (default: current folder)

Exit code: 0 if nothing failed, 1 if any check failed, 2 on a usage error.
`;

function readEnvFile(path: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of readFileSync(path, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (m) out[m[1]] = m[2].replace(/^'(.*)'$/, '$1').replace(/^"(.*)"$/, '$1');
  }
  return out;
}

async function keys(clientId: string | undefined, dir: string) {
  if (!clientId || !clientId.startsWith('https://')) {
    console.error('Give --client-id: the HTTPS URL where you will serve agent.json.');
    process.exit(2);
  }
  const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const pair = async (alg: 'ES256' | 'PS384') => {
    const { publicKey, privateKey } = await generateKeyPair(alg, alg === 'PS384' ? { extractable: true, modulusLength: 3072 } : { extractable: true });
    const kid = `${alg.toLowerCase()}-${stamp}`;
    return { pub: { ...(await exportJWK(publicKey)), kid, alg, use: 'sig' }, priv: { ...(await exportJWK(privateKey)), kid, alg, use: 'sig' } };
  };
  const es = await pair('ES256');
  const ps = await pair('PS384');
  const jwksUri = new URL('jwks.json', clientId).toString();
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'jwks.json'), JSON.stringify({ keys: [es.pub, ps.pub] }, null, 2) + '\n');
  writeFileSync(
    join(dir, 'agent.json'),
    JSON.stringify(
      { client_id: clientId, client_name: 'Poppy Readiness Check', jwks_uri: jwksUri, redirect_uris: [new URL('callback', clientId).toString()], token_endpoint_auth_method: 'private_key_jwt' },
      null,
      2,
    ) + '\n',
  );
  console.error(`Wrote ${join(dir, 'agent.json')} and ${join(dir, 'jwks.json')}.`);
  console.error(`Serve agent.json at exactly ${clientId} and jwks.json at ${jwksUri}, with no redirects.`);
  console.error(`Make sure ${new URL('missing-poppy-readiness.json', clientId)} returns 404.`);
  console.error('Keep these private and out of version control:\n');
  console.log(`POPPY_AGENT_CLIENT_ID=${clientId}`);
  console.log(`POPPY_AGENT_ES256_JWK=${JSON.stringify(es.priv)}`);
  console.log(`POPPY_AGENT_PS384_JWK=${JSON.stringify(ps.priv)}`);
}

async function check(domainArg: string | undefined, v: Record<string, any>) {
  const domain = normaliseDomain(domainArg);
  if (!domain) {
    console.error('Give a domain, such as example.com.');
    process.exit(2);
  }
  const env = { ...process.env, ...(v['env-file'] ? readEnvFile(v['env-file']) : {}) };
  const clientId = env.POPPY_AGENT_CLIENT_ID;
  const roots = await rootKeysFromEnv(env);
  if (!clientId || !roots) {
    console.error('Set POPPY_AGENT_CLIENT_ID, POPPY_AGENT_ES256_JWK and POPPY_AGENT_PS384_JWK (run `poppy-readiness keys` first), or pass --env-file.');
    process.exit(2);
  }
  const events: CheckEvent[] = [];
  let done: DoneEvent | undefined;
  const icon = { pass: '✓', fail: '✕', warn: '!', skip: '–' } as const;
  await runChecks({
    domain,
    identity: { clientId, userAgent: env.POPPY_AGENT_USER_AGENT },
    roots,
    readOnlyCalls: !!v['read-only'],
    sendFeedback: !!v.feedback,
    emit: (e) => {
      if (v.json) return console.log(JSON.stringify(e));
      if (e.type === 'check') {
        events.push(e);
        if (!v.markdown) console.log(`${icon[e.status]} ${e.status.padEnd(4)}  ${e.id.padEnd(3)}  ${e.title}${e.detail ? `\n                ${e.detail}` : ''}${e.http ? `\n                ${e.http}` : ''}`);
      } else if (e.type === 'log' && v.log && !v.markdown) console.log(`      #${e.n} ${e.method} ${e.url} → ${e.status ?? e.error}${e.note ? ` (${e.note})` : ''}`);
      else if (e.type === 'done') done = e;
    },
  });
  if (done && v.markdown) process.stdout.write(markdownReport(events, done));
  else if (done && !v.json) {
    console.log(`\n${done.domain}: ${done.passed} of ${done.passed + done.failed + done.warned} passed · ${done.failed} failed · ${done.warned} warnings · ${done.skipped} skipped`);
    console.log(`${COMPANY_TYPE_LABEL[done.companyType]} · identifier ${done.identifier ?? 'none'} · ${done.requests} requests · ${(done.ms / 1000).toFixed(1)} s`);
  }
  process.exit(done && done.failed === 0 ? 0 : 1);
}

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    'read-only': { type: 'boolean' },
    feedback: { type: 'boolean' },
    log: { type: 'boolean' },
    json: { type: 'boolean' },
    markdown: { type: 'boolean' },
    'env-file': { type: 'string' },
    'client-id': { type: 'string' },
    dir: { type: 'string' },
    help: { type: 'boolean', short: 'h' },
  },
});
const [cmd, arg] = positionals;
if (values.help || !cmd) {
  process.stdout.write(HELP);
  process.exit(cmd ? 0 : 2);
} else if (cmd === 'keys') await keys(values['client-id'], values.dir ?? '.');
else if (cmd === 'check') await check(arg, values);
else {
  process.stdout.write(HELP);
  process.exit(2);
}

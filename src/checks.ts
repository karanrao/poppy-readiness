// The readiness checks (stages A–E). Acts as a personal agent against one domain, emitting a
// `check` event per check, a `log` event per request, then exactly one `done`.
//
// Every check runs unless it genuinely depends on an earlier one: no poppy.json skips
// everything; a broken MCP server doesn't stop the tasks checks. Anything left when the time or
// request budget runs out is reported as `skip` with the reason.

import YAML from 'yaml';
import { LIMITS, resolveIdentity, type Identity } from './config.js';
import { CHECKS, CHECKS_BY_ID, type CheckEvent, type CompanyType, type RunEvent, type Status } from './catalogue.js';
import { Fetcher, NetError, parseJson, type FetchResult, type FetcherOptions } from './net.js';
import { Agent, type Forge, type RootKeys } from './signing.js';
import { McpClient, type McpTool } from './mcp.js';

type Json = Record<string, any>;

export interface RunOptions {
  domain: string;
  identity: Identity;
  roots: RootKeys;
  readOnlyCalls?: boolean;
  sendFeedback?: boolean;
  emit: (e: RunEvent) => void;
  fetcher?: Omit<FetcherOptions, 'onLog'>;
  signal?: AbortSignal;
}

const SESSION_ERRORS = ['invalid_session', 'session_ended', 'version_unsupported'];
const DIGEST = /^sha256:[0-9a-f]{64}$/;

const isObj = (v: unknown): v is Json => !!v && typeof v === 'object' && !Array.isArray(v);
const str = (v: unknown): v is string => typeof v === 'string' && v.trim().length > 0;
const http = (method: string, r: FetchResult | { url: string; status: number | null }) => `${method} ${r.url} → ${r.status ?? 'no response'}`;
const errCode = (r: FetchResult): string | undefined => {
  const j = parseJson(r.text);
  return isObj(j) && typeof j.error === 'string' ? j.error : undefined;
};
const list = (xs: string[], max = 6) => (xs.length > max ? `${xs.slice(0, max).join(', ')}, …` : xs.join(', '));

/** Every string in a document that looks like a URL, with its JSON path. */
function urlsIn(doc: unknown, path = ''): { path: string; url: string }[] {
  if (typeof doc === 'string') return /^[a-z][a-z0-9+.-]*:\/\//i.test(doc) ? [{ path: path || '(root)', url: doc }] : [];
  if (Array.isArray(doc)) return doc.flatMap((v, i) => urlsIn(v, `${path}[${i}]`));
  if (isObj(doc)) return Object.entries(doc).flatMap(([k, v]) => urlsIn(v, path ? `${path}.${k}` : k));
  return [];
}

export async function runChecks(o: RunOptions): Promise<void> {
  const started = Date.now();
  const done = new Map<string, CheckEvent>();
  const responses: { check?: string; res: FetchResult; method: string }[] = [];
  let companyType: CompanyType = 'unknown';
  let identifier: string | undefined;
  let version: string | undefined;

  const id = resolveIdentity(o.identity);
  const fetcher = new Fetcher({
    userAgent: id.userAgent,
    ...o.fetcher,
    onLog: (e) => o.emit({ type: 'log', ...e }),
  });

  const emitCheck = (id: string, status: Status, detail?: string, httpLine?: string) => {
    if (done.has(id)) return;
    const def = CHECKS_BY_ID.get(id)!;
    const ev: CheckEvent = { type: 'check', id, stage: def.stage, status, title: def.title, section: def.section };
    if (detail) ev.detail = detail;
    if (httpLine) ev.http = httpLine;
    done.set(id, ev);
    o.emit(ev);
  };
  const pass = (id: string, d?: string, h?: string) => emitCheck(id, 'pass', d, h);
  const fail = (id: string, d?: string, h?: string) => emitCheck(id, 'fail', d, h);
  const warn = (id: string, d?: string, h?: string) => emitCheck(id, 'warn', d, h);
  const skip = (id: string, d?: string) => emitCheck(id, 'skip', d);
  const skipAll = (ids: string[], why: string) => ids.forEach((id) => skip(id, why));
  const skipRest = (why: string) => CHECKS.forEach((c) => skip(c.id, why));

  /** Runs a step; a budget or cap error skips everything left with the reason. */
  const budgetStop = (err: unknown): boolean => {
    if (err instanceof NetError && (err.code === 'budget' || err.code === 'request_cap')) {
      skipRest(err.code === 'budget' ? `Time budget ran out (${LIMITS.runMs / 1000} seconds). Run the checks again to finish.` : `Request limit for one run reached (${LIMITS.maxRequests}).`);
      return true;
    }
    return false;
  };
  const netDetail = (err: unknown) => (err instanceof NetError ? err.message : 'Request failed.');

  const finish = () => {
    skipRest('Not run.');
    const all = [...done.values()];
    o.emit({
      type: 'done',
      domain: o.domain,
      passed: all.filter((c) => c.status === 'pass').length,
      failed: all.filter((c) => c.status === 'fail').length,
      warned: all.filter((c) => c.status === 'warn').length,
      skipped: all.filter((c) => c.status === 'skip').length,
      companyType,
      identifier,
      version,
      requests: fetcher.count,
      ms: Date.now() - started,
    });
  };

  try {
    // ================= Stage A: discovery =================
    const discoveryUrl = `https://${o.domain}/.well-known/poppy.json`;
    let res: FetchResult;
    try {
      res = await fetcher.request(discoveryUrl, { followRedirects: true, headers: { accept: 'application/json' }, note: 'discovery' });
    } catch (err) {
      if (budgetStop(err)) return finish();
      fail('A1', netDetail(err));
      skipRest('Depends on poppy.json, which couldn’t be read.');
      return finish();
    }
    const final = new URL(res.url);
    let doc: Json | undefined = parseJson(res.text);
    {
      const problems: string[] = [];
      if (res.redirectRefused) problems.push(`Redirect not followed: ${res.redirectRefused.reason}`);
      else if (res.status === 404) problems.push('No Poppy setup found at this address.');
      else if (res.status !== 200) problems.push(`Expected 200, got ${res.status}.`);
      else if (final.pathname !== '/.well-known/poppy.json' || final.search) problems.push(`After redirects the URL is ${final.pathname}${final.search}, not exactly /.well-known/poppy.json with no query.`);
      else if (!isObj(doc)) problems.push('The response isn’t a JSON object.');
      if (problems.length) {
        fail('A1', problems.join(' '), http('GET', res));
        skipRest('Depends on poppy.json, which couldn’t be read.');
        return finish();
      }
      const hops = fetcher.hops.length - 1;
      pass('A1', hops ? `${hops} redirect${hops > 1 ? 's' : ''}, all HTTPS. Final path /.well-known/poppy.json, no query.` : 'No redirects. Final path /.well-known/poppy.json, no query.');
    }
    const servedHost = final.hostname.toLowerCase();

    // A2: version
    {
      const pv = doc!.protocol_version;
      const sv = isObj(doc!.supported_versions) ? doc!.supported_versions : {};
      const ok = typeof pv === 'string' && /^\d+\.\d+$/.test(pv);
      const offered = [pv, ...Object.keys(sv)].filter((v): v is string => typeof v === 'string' && /^\d+\.\d+$/.test(v));
      const ours = offered.filter((v) => v.split('.')[0] === '1').sort((a, b) => Number(b.split('.')[1]) - Number(a.split('.')[1]));
      if (!ok) {
        fail('A2', `protocol_version must be major.minor, got ${JSON.stringify(pv)}.`);
      } else if (!ours.length) {
        warn('A2', `Offers only ${list(offered)}. The checking agent speaks 1.x, so it stops here.`);
        skipRest('The company offers no 1.x version.');
        return finish();
      } else if (pv.split('.')[0] !== '1') {
        // Use the 1.x document from supported_versions: HTTPS, same host, no redirects (§3.4).
        const altUrl = sv[ours[0]];
        try {
          const u = new URL(altUrl);
          if (u.protocol !== 'https:' || u.hostname.toLowerCase() !== servedHost) throw new Error('not same host');
          const r2 = await fetcher.request(u.toString(), { note: `poppy.json ${ours[0]}` });
          const d2 = parseJson(r2.text);
          if (r2.status !== 200 || !isObj(d2)) throw new Error('bad');
          doc = d2;
          warn('A2', `protocol_version is ${pv}; using the ${ours[0]} document from supported_versions.`);
        } catch (err) {
          if (budgetStop(err)) return finish();
          fail('A2', `supported_versions lists ${ours[0]} at ${String(altUrl)}, but it couldn’t be read (it must be HTTPS on ${servedHost}, with no redirect).`);
          skipRest('The 1.x document couldn’t be read.');
          return finish();
        }
      } else {
        pass('A2', `protocol_version ${pv}${offered.length > 1 ? `; also offers ${list(offered.filter((v) => v !== pv))}` : ''}. Speaking 1.0.`);
      }
      version = '1.0';
    }
    const d = doc!;
    const org = isObj(d.organization) ? d.organization : {};
    const orgDomain = typeof org.domain === 'string' ? org.domain.toLowerCase() : undefined;

    // A3
    if (!str(org.name) || !orgDomain) fail('A3', `organization.${!str(org.name) ? 'name' : 'domain'} is missing.`);
    else if (orgDomain !== servedHost) fail('A3', `organization.domain is ${orgDomain}, but the file was served by ${servedHost}.`);
    else pass('A3', `${org.name} · ${orgDomain}`);

    // A4
    const channels = ['apis', 'web', 'agent'].filter((k) => d[k] != null);
    if (!channels.length) fail('A4', 'None of apis, web or agent is present.');
    else pass('A4', channels.map((k) => (k === 'apis' && Array.isArray(d.apis) ? `apis (${d.apis.length})` : k)).join(', ') + '.');

    // A5
    {
      const urls = urlsIn(d).slice(0, 60);
      const bad: string[] = [];
      const hosts = new Map<string, string>();
      for (const { path, url } of urls) {
        try {
          const u = new URL(url);
          if (u.protocol !== 'https:') bad.push(`${path} isn’t HTTPS`);
          else if (!hosts.has(u.hostname)) hosts.set(u.hostname, path);
        } catch {
          bad.push(`${path} isn’t a valid URL`);
        }
      }
      for (const [host, path] of [...hosts].slice(0, 20)) {
        try {
          await fetcher.vet(`https://${host}/`);
        } catch (err) {
          if (err instanceof NetError && err.code === 'refused_private') bad.push(`${path}: refused, private address`);
          else if (err instanceof NetError && err.code === 'network') bad.push(`${path}: ${host} doesn’t resolve`);
        }
      }
      if (bad.length) fail('A5', bad.slice(0, 5).join('; ') + '.');
      else pass('A5', `${urls.length} URL${urls.length === 1 ? '' : 's'} checked.`);
    }

    // A6
    const apis: Json[] = Array.isArray(d.apis) ? d.apis.filter(isObj) : [];
    const protocols: Json[] = isObj(d.agent) && Array.isArray(d.agent.protocols) ? d.agent.protocols.filter(isObj) : [];
    {
      const missing: string[] = [];
      apis.forEach((a, i) => ['type', 'url', 'description'].forEach((k) => !str(a[k]) && missing.push(`apis[${i}].${k}`)));
      protocols.forEach((p, i) => ['type', 'endpoint', 'description'].forEach((k) => !str(p[k]) && missing.push(`agent.protocols[${i}].${k}`)));
      if (!apis.length && !protocols.length) skip('A6', 'No apis or agent.protocols entries.');
      else if (missing.length) fail('A6', `Missing: ${list(missing)}. 1.0 requires a description on conversation endpoints.`);
      else pass('A6', `${apis.length} API${apis.length === 1 ? '' : 's'}, ${protocols.length} conversation endpoint${protocols.length === 1 ? '' : 's'}.`);
    }

    // A7
    const auth = isObj(d.auth) ? d.auth : undefined;
    {
      const hints = auth?.scope_hints;
      if (hints == null) skip('A7', 'Not applicable: no scope hints.');
      else {
        const entries: [string, unknown][] = Array.isArray(hints) ? hints.map((h, i) => [String(h?.scope ?? i), h]) : isObj(hints) ? Object.entries(hints) : [];
        const bad = entries.filter(([, h]) => !isObj(h) || !['none', 'reversible', 'irreversible'].includes(h.changes) || h.personal_data === undefined).map(([k]) => k);
        if (!entries.length) fail('A7', 'scope_hints is present but empty or not a list.');
        else if (bad.length) fail('A7', `Each hint needs changes (none, reversible or irreversible) and personal_data. Check: ${list(bad)}.`);
        else pass('A7', `${entries.length} scope hint${entries.length === 1 ? '' : 's'}, each with changes and personal_data.`);
      }
    }

    // A8
    if (isObj(d.web) && d.web.unscoped === true) {
      if (str(d.web.browser_session_endpoint)) pass('A8', 'web.unscoped comes with a browser_session_endpoint.');
      else fail('A8', 'web.unscoped is true but there’s no browser_session_endpoint.');
    } else skip('A8', 'Not applicable: web.unscoped isn’t set.');

    // A9 – A11: issuer and identifier
    let issuer: string | undefined;
    const signInOffered = str(auth?.issuer) || protocols.some((p) => p.access === 'signed_in');
    const orgResource = orgDomain ? `https://${orgDomain}` : undefined;
    let identifierOk = false;
    {
      const prmUrl = `https://${o.domain}/.well-known/oauth-protected-resource`;
      let prm: FetchResult | undefined;
      try {
        prm = await fetcher.request(prmUrl, { headers: { accept: 'application/json' }, note: 'protected resource metadata' });
      } catch (err) {
        if (budgetStop(err)) return finish();
        fail('A9', `${netDetail(err)} Agents must not fall back to the domain after an error (§3.2).`);
      }
      const noIssuer = (how: string) => {
        if (signInOffered) fail('A9', `${how}, but poppy.json offers sign-in${str(auth?.issuer) ? ` (auth.issuer ${auth!.issuer})` : ''}. Sign-in needs an issuer.`);
        else {
          pass('A9', `Signed out only (no issuer): ${how}.`);
          companyType = 'signed-out';
          identifierOk = true;
        }
      };
      if (prm) {
        const meta = parseJson(prm.text);
        if (prm.redirectRefused) fail('A9', `Redirected (${prm.status}). Agents don’t follow redirects here.`, http('GET', prm));
        else if (prm.status === 404) noIssuer('404');
        else if (prm.status !== 200 || !isObj(meta)) fail('A9', `${prm.status !== 200 ? `Got ${prm.status}` : 'Invalid JSON'}. Agents must not fall back to the domain (§3.2).`, http('GET', prm));
        else if (meta.resource !== orgResource) fail('A9', `resource is ${JSON.stringify(meta.resource)}; it must be exactly ${orgResource}.`, http('GET', prm));
        else {
          const servers = Array.isArray(meta.authorization_servers) ? meta.authorization_servers.filter(str) : [];
          if (!servers.length) noIssuer('200 with no authorization servers');
          else if (servers.length === 1) {
            issuer = servers[0];
            pass('A9', `Has an issuer: ${issuer}.`);
          } else if (str(auth?.issuer) && servers.includes(auth!.issuer)) {
            issuer = auth!.issuer;
            pass('A9', `${servers.length} authorization servers; auth.issuer picks ${issuer}.`);
          } else fail('A9', `${servers.length} authorization servers, and auth.issuer ${str(auth?.issuer) ? `(${auth!.issuer}) isn’t one of them` : 'doesn’t name one'}.`);
          if (issuer) {
            companyType = 'issuer';
            identifierOk = true;
          }
        }
      }
    }
    if (identifierOk) {
      identifier = (issuer ?? orgResource!).toLowerCase().replace(/\/+$/, '');
      pass('A10', `${identifier}. Used as aud in every Session JWT.`);
    } else skip('A10', 'No identifier: protected resource metadata (A9) failed, and agents mustn’t fall back to the domain.');
    o.emit({ type: 'meta', domain: o.domain, companyType, identifier, version });

    if (issuer) {
      const base = new URL(issuer);
      const path = base.pathname === '/' ? '' : base.pathname.replace(/\/$/, '');
      const candidates = [`${base.origin}/.well-known/oauth-authorization-server${path}`, `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`];
      let meta: Json | undefined;
      let last: FetchResult | undefined;
      for (const u of candidates) {
        try {
          last = await fetcher.request(u, { headers: { accept: 'application/json' }, note: 'issuer metadata' });
          const j = parseJson(last.text);
          if (last.status === 200 && isObj(j)) {
            meta = j;
            break;
          }
        } catch (err) {
          if (budgetStop(err)) return finish();
        }
      }
      if (!meta) fail('A11', 'No RFC 8414 or OpenID metadata at the issuer.', last ? http('GET', last) : undefined);
      else if (meta.issuer !== issuer) fail('A11', `issuer in the metadata is ${JSON.stringify(meta.issuer)}; it must match ${issuer} exactly.`, last && http('GET', last));
      else if (!Array.isArray(meta.protected_resources) || !meta.protected_resources.includes(orgResource)) fail('A11', `protected_resources doesn’t include ${orgResource}.`, last && http('GET', last));
      else {
        const kinds: string[] = [];
        const grants: string[] = Array.isArray(meta.grant_types_supported) ? meta.grant_types_supported : ['authorization_code'];
        if (grants.includes('authorization_code') && (meta.code_challenge_methods_supported ?? []).includes('S256')) kinds.push('authorization code with PKCE');
        if (grants.includes('urn:ietf:params:oauth:grant-type:device_code')) kinds.push('device grant');
        const bits = [`Sign-in: ${kinds.join(', ') || 'no PKCE authorization code listed'}`];
        if (meta.require_pushed_authorization_requests) bits.push('pushed authorization requests required');
        if (auth?.disabled === true) bits.push('has an issuer, sign-in off (auth.disabled)');
        pass('A11', bits.join('. ') + '. The checking agent never starts a sign-in.');
      }
    } else skip('A11', (companyType as CompanyType) === 'signed-out' ? 'Not applicable: no issuer.' : 'No issuer found.');

    if (!identifier) {
      skipRest('Session checks need a company identifier, and A9 didn’t give one.');
      return finish();
    }

    // ================= Sessions from here on =================
    const agent = new Agent({ roots: o.roots, clientId: id.clientId, aud: identifier, version });
    const sign = (f?: Forge) => agent.signer(f);
    const tasksUrl = isObj(d.tasks) && str(d.tasks.endpoint) ? d.tasks.endpoint : undefined;
    const mcpApi = apis.find((a) => a.type === 'mcp' && str(a.url));
    const openapiApi = apis.find((a) => a.type === 'openapi' && str(a.url));
    const otherApis = apis.filter((a) => a.type !== 'mcp' && a.type !== 'openapi');

    // D1 first: it's B1's preferred endpoint.
    let tasksRes: FetchResult | undefined;
    let tasksDoc: Json | undefined;
    if (tasksUrl) {
      try {
        tasksRes = await fetcher.request(tasksUrl, { headers: { accept: 'application/json' }, sign: sign(), note: 'tasks' });
        responses.push({ res: tasksRes, method: 'GET' });
        tasksDoc = parseJson(tasksRes.text);
        if (tasksRes.redirectRefused) fail('D1', tasksRes.redirectRefused.reason, http('GET', tasksRes));
        else if (tasksRes.status === 200 && isObj(tasksDoc)) {
          pass('D1', `200 JSON${['excluded_tasks', 'skill_index', 'feedback'].filter((k) => tasksDoc![k] != null).map((k) => ` · ${k}${k === 'excluded_tasks' && Array.isArray(tasksDoc!.excluded_tasks) ? ` (${tasksDoc!.excluded_tasks.length})` : ''}`).join('')}.`);
        } else fail('D1', tasksRes.status === 200 ? 'The response isn’t a JSON object.' : `Expected 200, got ${tasksRes.status}${errCode(tasksRes) ? ` (${errCode(tasksRes)})` : ''}.`, http('GET', tasksRes));
      } catch (err) {
        if (budgetStop(err)) return finish();
        fail('D1', netDetail(err));
      }
    } else skipAll(['D1', 'D2', 'D3', 'D4', 'D5', 'D6'], 'No tasks endpoint in poppy.json (it’s optional).');

    const b1From = (r: FetchResult, what: string, method = 'GET') => {
      const code = errCode(r);
      if (r.status === 400 && code && ['invalid_session', 'version_unsupported'].includes(code)) fail('B1', `${what} refused a valid signed-out Session: ${code}.`, http(method, r));
      else if (r.status === 401) warn('B1', `${what} answered 401: it wants an account even for signed-out requests.`, http(method, r));
      else pass('B1', `${what} answered ${r.status}.`);
    };
    if (tasksRes) b1From(tasksRes, 'Tasks endpoint');

    // ================= Stage C: APIs =================
    let mcp: McpClient | undefined;
    let tools: McpTool[] | null = null;
    let mcpReachable = false;
    let readOnlyCalls = 0;
    if (mcpApi) {
      mcp = new McpClient(mcpApi.url, fetcher, agent);
      try {
        const r = await mcp.initialize();
        responses.push({ res: r.res, method: 'POST' });
        const result = r.message?.result;
        if (r.res.redirectRefused) fail('C1', r.res.redirectRefused.reason, http('POST', r.res));
        else if (result) {
          mcpReachable = true;
          const info = result.serverInfo ?? {};
          pass('C1', `${[info.name, info.version].filter(Boolean).join(' ') || 'Unnamed server'} · MCP ${result.protocolVersion ?? '?'} · ${str(result.instructions) ? 'instructions present' : 'no instructions'}.`);
        } else if (r.message?.error?.code === -32601) {
          mcpReachable = true;
          warn('C1', 'No initialize method (newer MCP versions drop the handshake). Carried on without it.');
        } else fail('C1', `No initialize result${errCode(r.res) ? `: ${errCode(r.res)}` : ''}.`, http('POST', r.res));
        if (!tasksRes) b1From(r.res, 'The MCP server', 'POST');
      } catch (err) {
        if (budgetStop(err)) return finish();
        fail('C1', netDetail(err));
      }
      try {
        const { reply, tools: t } = await mcp.listTools();
        responses.push({ res: reply.res, method: 'POST' });
        tools = t;
        if (t) {
          mcpReachable = true;
          pass('C2', `${t.length} tool${t.length === 1 ? '' : 's'}${t.length ? `: ${list(t.map((x) => x.name), 8)}` : ''}.`);
        } else fail('C2', `No tools/list result${errCode(reply.res) ? `: ${errCode(reply.res)}` : ''}.`, http('POST', reply.res));
      } catch (err) {
        if (budgetStop(err)) return finish();
        fail('C2', netDetail(err));
      }
      // C3: read-only call
      if (!o.readOnlyCalls) skip('C3', 'Not ticked.');
      else if (!tools) skip('C3', 'No tool list.');
      else {
        const safe = tools.filter((t) => {
          if (t.annotations?.readOnlyHint !== true || t.annotations?.destructiveHint === true) return false;
          const props = isObj(t.inputSchema?.properties) ? t.inputSchema.properties : {};
          const req: string[] = Array.isArray(t.inputSchema?.required) ? t.inputSchema.required : [];
          return req.every((k) => props[k]?.type === 'string');
        });
        if (!safe.length) skip('C3', 'No tool is safe to call: none is marked readOnlyHint with inputs the checking agent can fill harmlessly.');
        else {
          const out: string[] = [];
          let protocolProblem = false;
          for (const t of safe.slice(0, LIMITS.maxReadOnlyCalls - readOnlyCalls)) {
            const req: string[] = Array.isArray(t.inputSchema?.required) ? t.inputSchema.required : [];
            const args = Object.fromEntries(req.map((k) => [k, 'poppy-readiness-check']));
            readOnlyCalls++;
            try {
              const r = await mcp.callTool(t.name, args);
              const result = r.message?.result;
              if (!result) protocolProblem = true;
              out.push(`${t.name}: ${result ? (result.isError ? 'isError true (a tool error, not a protocol problem)' : 'ok') : `no result (${r.res.status})`}`);
            } catch (err) {
              if (budgetStop(err)) return finish();
              out.push(`${t.name}: ${netDetail(err)}`);
              protocolProblem = true;
            }
          }
          (protocolProblem ? fail : pass)('C3', out.join('; ') + '.');
        }
      }
      // C4
      if (!tools) skip('C4', 'No tool list.');
      else {
        const noDesc = tools.filter((t) => !str(t.description)).map((t) => t.name);
        const noAnn = tools.filter((t) => !isObj(t.annotations) || !Object.keys(t.annotations).length).map((t) => t.name);
        const bits: string[] = [];
        if (noDesc.length) bits.push(`${noDesc.length} without a description: ${list(noDesc)}`);
        if (noAnn.length) bits.push(`${noAnn.length} without annotations: ${list(noAnn)}`);
        if (bits.length) warn('C4', `${bits.join('. ')}. Agents choose tools by these.`);
        else pass('C4', tools.length ? 'Every tool has a description and annotations.' : 'No tools to check.');
      }
    } else skipAll(['C1', 'C2', 'C3', 'C4'], 'No MCP server in apis.');

    // C5 / C6: OpenAPI
    let operationIds = new Set<string>();
    let openapiGet: string | undefined;
    if (openapiApi) {
      try {
        const r = await fetcher.request(openapiApi.url, { headers: { accept: 'application/json, application/yaml;q=0.9' }, sign: sign(), note: 'OpenAPI document' });
        responses.push({ res: r, method: 'GET' });
        let spec: any = parseJson(r.text);
        if (spec === undefined) {
          try {
            spec = YAML.parse(r.text);
          } catch {
            spec = undefined;
          }
        }
        if (r.status !== 200 || !isObj(spec)) fail('C5', r.status !== 200 ? `Expected 200, got ${r.status}.` : 'Neither JSON nor YAML.', http('GET', r));
        else if (typeof spec.openapi !== 'string' || !spec.openapi.startsWith('3.')) fail('C5', `Not OpenAPI 3.x (openapi is ${JSON.stringify(spec.openapi ?? spec.swagger)}).`, http('GET', r));
        else {
          const ops: { method: string; path: string; op: Json; params: Json[] }[] = [];
          for (const [p, item] of Object.entries<Json>(isObj(spec.paths) ? spec.paths : {})) {
            for (const m of ['get', 'put', 'post', 'delete', 'patch', 'head', 'options']) {
              if (isObj(item?.[m])) ops.push({ method: m.toUpperCase(), path: p, op: item[m], params: [...(item.parameters ?? []), ...(item[m].parameters ?? [])] });
            }
          }
          operationIds = new Set(ops.map((x) => x.op.operationId).filter(str));
          pass('C5', `${spec.info?.title ?? 'Untitled'} · OpenAPI ${spec.openapi} · ${ops.length} operation${ops.length === 1 ? '' : 's'}.`);
          const serverUrl = Array.isArray(spec.servers) && str(spec.servers[0]?.url) ? new URL(spec.servers[0].url, r.url).toString() : new URL('/', r.url).toString();
          const getOps = ops.filter((x) => x.method === 'GET' && !x.path.includes('{') && !x.params.some((p) => p?.required) && !x.op.requestBody?.required);
          if (getOps[0]) openapiGet = serverUrl.replace(/\/$/, '') + getOps[0].path;
          // C6
          if (!o.readOnlyCalls) skip('C6', 'Not ticked.');
          else if (!getOps.length) skip('C6', 'No GET operation without required parameters.');
          else {
            const out: string[] = [];
            let bad = false;
            for (const g of getOps.slice(0, Math.max(0, LIMITS.maxReadOnlyCalls - readOnlyCalls))) {
              readOnlyCalls++;
              try {
                const rr = await fetcher.request(serverUrl.replace(/\/$/, '') + g.path, { headers: { accept: 'application/json' }, sign: sign(), note: g.op.operationId ?? g.path });
                responses.push({ res: rr, method: 'GET' });
                const code = errCode(rr);
                if (rr.status >= 500 || (rr.status === 400 && code && SESSION_ERRORS.includes(code))) bad = true;
                out.push(`${g.op.operationId ?? g.path} → ${rr.status}${code ? ` ${code}` : ''}`);
              } catch (err) {
                if (budgetStop(err)) return finish();
                out.push(`${g.op.operationId ?? g.path}: ${netDetail(err)}`);
                bad = true;
              }
            }
            if (!out.length) skip('C6', `The read-only call limit (${LIMITS.maxReadOnlyCalls}) was used by MCP tools.`);
            else (bad ? fail : pass)('C6', out.join('; ') + '.');
          }
        }
      } catch (err) {
        if (budgetStop(err)) return finish();
        fail('C5', netDetail(err));
      }
    }
    if (!done.has('C5')) skip('C5', 'No OpenAPI API in apis.');
    if (!done.has('C6')) skip('C6', 'No OpenAPI API in apis.');
    if (otherApis.length) warn('C7', `Not tested: ${list(otherApis.map((a) => String(a.type ?? 'no type')))}. Agents skip API types they don’t recognise.`);
    else skip('C7', 'Not applicable: only MCP and OpenAPI APIs listed.');

    if (!done.has('B1')) {
      if (openapiGet) {
        try {
          const r = await fetcher.request(openapiGet, { headers: { accept: 'application/json' }, sign: sign(), note: 'B1 OpenAPI GET' });
          responses.push({ res: r, method: 'GET' });
          b1From(r, 'The API');
        } catch (err) {
          if (budgetStop(err)) return finish();
          skip('B1', netDetail(err));
        }
      } else skip('B1', 'No endpoint that takes a Session (tasks, MCP or an OpenAPI GET).');
    }

    // ================= Stage D: tasks and feedback =================
    if (tasksUrl && isObj(tasksDoc) && tasksRes?.status === 200) {
      // D2
      const ex = tasksDoc.excluded_tasks;
      if (ex == null) pass('D2', 'No excluded tasks listed (optional).');
      else if (!Array.isArray(ex)) fail('D2', 'excluded_tasks must be a list.');
      else {
        const problems: string[] = [];
        const notes: string[] = [];
        const mcpUrls = apis.filter((a) => a.type === 'mcp').map((a) => a.url);
        const oaUrls = apis.filter((a) => a.type === 'openapi').map((a) => a.url);
        const toolNames = new Set((tools ?? []).map((t) => t.name));
        ex.forEach((e: Json, i: number) => {
          if (!isObj(e) || !str(e.task)) return problems.push(`excluded_tasks[${i}] has no task`);
          const alt = e.alternative;
          if (alt == null) return;
          if (!isObj(alt) || (!str(alt.instructions) && !Array.isArray(alt.references))) return problems.push(`excluded_tasks[${i}].alternative needs instructions or references`);
          (Array.isArray(alt.references) ? alt.references : []).forEach((ref: Json, j: number) => {
            const at = `excluded_tasks[${i}].alternative.references[${j}]`;
            if (!isObj(ref)) return problems.push(`${at} isn’t an object`);
            if (ref.type === 'web') {
              if (!str(ref.url) || !ref.url.startsWith('https://')) problems.push(`${at} needs an HTTPS url`);
            } else if (ref.type === 'mcp') {
              if (!str(ref.url) || !str(ref.tool)) problems.push(`${at} needs url and tool`);
              else if (!mcpUrls.includes(ref.url)) notes.push(`${at} names an MCP server that isn’t in apis, so agents ignore it`);
              else if (tools && !toolNames.has(ref.tool)) problems.push(`${at} references MCP tool ${ref.tool}, which isn’t in tools/list`);
            } else if (ref.type === 'openapi') {
              if (!str(ref.url) || !str(ref.operation_id)) problems.push(`${at} needs url and operation_id`);
              else if (!oaUrls.includes(ref.url)) notes.push(`${at} names an OpenAPI document that isn’t in apis, so agents ignore it`);
              else if (operationIds.size && !operationIds.has(ref.operation_id)) problems.push(`${at} references operation ${ref.operation_id}, which isn’t in the OpenAPI document`);
            } else notes.push(`${at} has type ${JSON.stringify(ref.type)}, which agents skip`);
          });
        });
        if (problems.length) fail('D2', problems.slice(0, 4).join('; ') + '.');
        else if (notes.length) warn('D2', notes.slice(0, 3).join('; ') + '.');
        else pass('D2', `${ex.length} excluded task${ex.length === 1 ? '' : 's'}, references check out.`);
      }
      // D3
      const si = tasksDoc.skill_index;
      if (si == null) skip('D3', 'Not applicable: no skill_index.');
      else if (!isObj(si)) fail('D3', 'skill_index must be an object.');
      else {
        const skills: Json[] = Array.isArray(si.skills) ? si.skills : [];
        const bad: string[] = [];
        skills.forEach((s, i) => {
          const miss = ['name', 'description', 'type', 'url', 'digest'].filter((k) => !str(s?.[k]));
          if (miss.length) bad.push(`skills[${i}] missing ${miss.join(', ')}`);
          else if (!DIGEST.test(s.digest)) bad.push(`skills[${i}].digest isn’t sha256: plus 64 lowercase hex characters`);
        });
        const unknownTypes = skills.filter((s) => str(s?.type) && !['skill-md', 'archive'].includes(s.type)).length;
        if (!String(si.$schema ?? '').includes('0.2.0')) warn('D3', `$schema is ${si.$schema ? JSON.stringify(si.$schema) : 'missing'}. Agents ignore an index without the 0.2.0 schema.`);
        else if (bad.length) fail('D3', bad.slice(0, 4).join('; ') + '.');
        else if (unknownTypes) warn('D3', `${unknownTypes} skill${unknownTypes > 1 ? 's have' : ' has'} a type other than skill-md or archive; agents skip them.`);
        else pass('D3', `${skills.length} skill${skills.length === 1 ? '' : 's'}, digests well formed.`);
      }
      // D4
      const fbUrl = isObj(tasksDoc.feedback) ? tasksDoc.feedback.endpoint : undefined;
      if (fbUrl == null) skip('D4', 'Not applicable: no feedback endpoint.');
      else if (!str(fbUrl) || !fbUrl.startsWith('https://')) fail('D4', `feedback.endpoint must be HTTPS, got ${JSON.stringify(fbUrl)}.`);
      else pass('D4', fbUrl);
      // D5
      if (!o.sendFeedback) skip('D5', 'Not ticked.');
      else if (!str(fbUrl) || !fbUrl.startsWith('https://')) skip('D5', 'No HTTPS feedback endpoint.');
      else {
        try {
          const r = await fetcher.request(fbUrl, {
            method: 'POST',
            headers: { 'content-type': 'application/json', accept: 'application/json' },
            body: JSON.stringify({
              task: 'Poppy Readiness Check test',
              description: `Automated test from a Poppy Readiness Check (${id.userAgent}). Safe to delete.`.slice(0, 2000),
            }),
            sign: sign(),
            note: 'feedback (ticked)',
          });
          responses.push({ res: r, method: 'POST' });
          if (r.status === 202) pass('D5', `202${r.text.trim() ? ', though the spec says no body' : ', no body'}.`);
          else if (r.status === 200 && isObj(parseJson(r.text))) pass('D5', '200 with an alternative: the company says the task can be done after all.');
          else fail('D5', `Expected 202, got ${r.status}${errCode(r) ? ` ${errCode(r)}` : ''}.`, http('POST', r));
        } catch (err) {
          if (budgetStop(err)) return finish();
          fail('D5', netDetail(err));
        }
      }
      // D6
      try {
        const other = new Agent({ roots: o.roots, clientId: id.clientId, aud: identifier, version });
        const r2 = await fetcher.request(tasksUrl, { headers: { accept: 'application/json' }, sign: other.signer(), note: 'tasks, second Session' });
        const norm = (t: string) => {
          const j = parseJson(t);
          return j === undefined ? t : JSON.stringify(j);
        };
        if (norm(r2.text) === norm(tasksRes.text)) pass('D6', 'Same response for two Sessions; no private marking needed.');
        else {
          const cc = [tasksRes.headers.get('cache-control'), r2.headers.get('cache-control')].map((v) => (v ?? '').toLowerCase());
          if (cc.every((v) => /\b(private|no-store)\b/.test(v))) pass('D6', 'Responses differ between Sessions and are marked private or no-store.');
          else fail('D6', `Responses differ between Sessions, but Cache-Control is ${JSON.stringify(cc[1] || cc[0] || 'missing')}. It must be private or no-store.`);
        }
      } catch (err) {
        if (budgetStop(err)) return finish();
        skip('D6', netDetail(err));
      }
    } else if (tasksUrl) skipAll(['D2', 'D3', 'D4', 'D5', 'D6'], 'The tasks endpoint didn’t answer with JSON (D1).');

    // ================= Stage E: requests a company must refuse =================
    type Target = { name: string; url: string; send: (f: Forge) => Promise<FetchResult> };
    let target: Target | undefined;
    if (mcp && mcpReachable) {
      const m = mcp;
      target = { name: 'MCP tools/list', url: m.url, send: async (f) => (await m.rpc('tools/list', {}, { forge: f, note: 'refusal check' })).res };
    } else if (tasksUrl) {
      target = { name: 'the tasks endpoint', url: tasksUrl, send: (f) => fetcher.request(tasksUrl, { headers: { accept: 'application/json' }, sign: sign(f), note: 'refusal check' }) };
    } else if (openapiGet) {
      const g = openapiGet;
      target = { name: 'an OpenAPI GET', url: g, send: (f) => fetcher.request(g, { headers: { accept: 'application/json' }, sign: sign(f), note: 'refusal check' }) };
    }
    const eIds = CHECKS.filter((c) => c.stage === 'E').map((c) => c.id);
    if (!target) skipAll(eIds, 'No endpoint that takes a Session.');
    else {
      const t = target;
      const cases: [string, Forge, string][] = [
        ['E14', { raw: 'x' }, 'invalid_session'],
        ['E1', { version: null }, 'version_unsupported'],
        ['E2', { version: '99.0' }, 'version_unsupported'],
        ['E3', { aud: 'https://example.invalid' }, 'invalid_session'],
        ['E4', { htu: `${new URL(t.url).origin}/poppy-readiness-wrong-path` }, 'invalid_session'],
        ['E5', { htm: t.name.startsWith('MCP') ? 'GET' : 'POST' }, 'invalid_session'],
        ['E6', { iatOffset: -600 }, 'invalid_session'],
        ['E7', { kid: 'not-the-delegated-key' }, 'invalid_session'],
        ['E8', { wrongSessionKey: true }, 'invalid_session'],
        ['E9', { unknownRootKey: true }, 'invalid_session'],
        ['E10', { delegationLifetime: 25 * 3600 }, 'invalid_session'],
        ['E11', { delegationIatOffset: -7200, delegationLifetime: 3600 }, 'invalid_session'],
        ['E12', { extraClaims: { ath: 'fQ5Wl4x5o3kQyZxLhR6m7d2v0yQp8VbN1c3tYk9Hj2A' } }, 'invalid_session'],
        ['E13', { iss: id.missingClientId }, 'invalid_session'],
      ];
      let verifies: boolean | undefined;
      for (const [id, forge, expected] of cases) {
        let r: FetchResult;
        try {
          r = await t.send(forge);
        } catch (err) {
          if (budgetStop(err)) return finish();
          skip(id, netDetail(err));
          continue;
        }
        responses.push({ check: id, res: r, method: 'POST' });
        const code = errCode(r);
        const refused400 = r.status === 400 && !!code;
        if (id === 'E14' || id === 'E1') verifies = verifies || refused400 || r.status === 401;
        if (refused400 && code === expected) pass(id, `400 ${code}`);
        else if (refused400) warn(id, `Refused with 400 ${code}; ${expected} is the code for this case.`, http('POST', r));
        else if (r.status === 400) warn(id, `Refused with 400 but no JSON error code. Session errors are a JSON body {"error": "${expected}"}.`, http('POST', r));
        else if (r.status === 401 || r.status === 403) fail(id, `Refused with ${r.status}. Session errors must be 400, so OAuth libraries don’t throw away a valid token (§5.3).`, http('POST', r));
        else if (id === 'E1' && verifies) fail(id, `Accepted a request with a Session header but no Poppy-Version (${r.status}). An endpoint that verifies Sessions must refuse it with 400 version_unsupported (§3.4).`, http('POST', r));
        else if (verifies) fail(id, `Accepted a Session that should be refused (${t.name} answered ${r.status}). It verifies Sessions, so this one should fail too.`, http('POST', r));
        else warn(id, `Accepted a Session that should be refused (${r.status}). ${t.name} doesn’t seem to verify Sessions, which §7 and §9 allow when responses don’t depend on the Session.`, http('POST', r));
      }
      // E15: positive check
      try {
        const r = await t.send({ ps384: true });
        responses.push({ check: 'E15', res: r, method: 'POST' });
        const code = errCode(r);
        if (r.status === 400 && code && SESSION_ERRORS.includes(code)) {
          if (verifies) fail('E15', `Refused a delegation signed with PS384 (${code}). Companies must accept ES256 and PS384.`, http('POST', r));
          else warn('E15', `Refused with ${code}.`, http('POST', r));
        } else if (verifies) pass('E15', `Accepted (${r.status}), as it must be.`);
        else skip('E15', `Can’t tell: ${t.name} doesn’t verify Sessions.`);
      } catch (err) {
        if (budgetStop(err)) return finish();
        skip('E15', netDetail(err));
      }
    }

    // B2: how Session errors looked across the whole run
    {
      const sessionErrs = responses.filter(({ res }) => {
        const code = errCode(res);
        return res.status === 400 && !!code && SESSION_ERRORS.includes(code);
      });
      const wrong = responses.filter(({ check, res }) => check && done.get(check)?.status === 'fail' && (res.status === 401 || res.status === 403));
      const noJson = responses.filter(({ check, res }) => check && res.status === 400 && !errCode(res));
      if (wrong.length) fail('B2', `${wrong.length} refusal${wrong.length > 1 ? 's' : ''} used ${wrong[0].res.status} instead of 400.`, http(wrong[0].method, wrong[0].res));
      else if (noJson.length) fail('B2', `${noJson.length} refusal${noJson.length > 1 ? 's' : ''} had no JSON error body.`, http(noJson[0].method, noJson[0].res));
      else if (sessionErrs.length) pass('B2', `${sessionErrs.length} Session error${sessionErrs.length > 1 ? 's' : ''}, all 400 with a JSON error code.`);
      else skip('B2', 'No Session errors seen in this run.');
    }
  } catch (err) {
    if (!budgetStop(err)) {
      console.error(JSON.stringify({ evt: 'prc_error', name: (err as any)?.name, message: String((err as any)?.message ?? '').slice(0, 200) }));
      skipRest('Something went wrong on our side. Run the checks again.');
    }
  }
  finish();
}

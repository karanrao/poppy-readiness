// Every readiness check, in report order, and the event types a run emits. No Node imports:
// a browser can import this to draw the empty report before results stream in.

export type Status = 'pass' | 'fail' | 'warn' | 'skip';
export type StageId = 'A' | 'B' | 'C' | 'D' | 'E';

export interface CheckDef {
  id: string;
  stage: StageId;
  title: string;
  section: string;
}

export const STAGES: { id: StageId; title: string; section: string }[] = [
  { id: 'A', title: 'A · Discovery', section: '§3' },
  { id: 'B', title: 'B · Signed-out Session', section: '§5' },
  { id: 'C', title: 'C · APIs', section: '§7' },
  { id: 'D', title: 'D · Tasks and feedback', section: '§9' },
  { id: 'E', title: 'E · Requests a company must refuse', section: '§3.4, §5.2, §5.3' },
];

const c = (id: string, title: string, section: string): CheckDef => ({ id, stage: id[0] as StageId, title, section });

export const CHECKS: CheckDef[] = [
  c('A1', 'poppy.json is readable', '§3'),
  c('A2', 'Protocol version', '§3.1, §3.4'),
  c('A3', 'Organisation matches the host', '§3.1'),
  c('A4', 'Offers at least one channel', '§3.1'),
  c('A5', 'Every URL is HTTPS and public', '§3'),
  c('A6', 'Entries carry type, URL and description', '§3.1'),
  c('A7', 'Scope hints are well formed', '§3.1'),
  c('A8', 'Unscoped web has a browser session endpoint', '§3.1'),
  c('A9', 'Protected resource metadata', '§3.2'),
  c('A10', 'Company identifier', '§3.2, §5.2'),
  c('A11', 'Issuer metadata', '§3.2'),
  c('B1', 'Accepts a valid signed-out Session', '§5.3'),
  c('B2', 'Session errors are 400 with JSON', '§5.3'),
  c('C1', 'MCP initialize', '§7'),
  c('C2', 'MCP tools/list', '§7'),
  c('C3', 'Read-only tool call', '§7'),
  c('C4', 'Tools have descriptions and annotations', '§7'),
  c('C5', 'OpenAPI document loads', '§7'),
  c('C6', 'Read-only GET operations', '§7'),
  c('C7', 'Other API types', '§7'),
  c('D1', 'Tasks endpoint answers', '§9'),
  c('D2', 'Excluded tasks and their references', '§9'),
  c('D3', 'Skill index', '§9'),
  c('D4', 'Feedback endpoint is HTTPS', '§9'),
  c('D5', 'Test feedback report', '§9'),
  c('D6', 'Caching between Sessions', '§9'),
  c('E1', 'No Poppy-Version', '§3.4'),
  c('E2', 'Poppy-Version 99.0', '§3.4'),
  c('E3', 'aud for another company', '§5.3'),
  c('E4', 'htu for a different path', '§5.3'),
  c('E5', 'htm for a different method', '§5.3'),
  c('E6', 'iat 10 minutes old', '§5.3'),
  c('E7', 'kid isn’t the delegated key’s thumbprint', '§5.2'),
  c('E8', 'Session signed by a key other than cnf.jwk', '§5.3'),
  c('E9', 'Delegation signed by a key not in jwks_uri', '§5.3'),
  c('E10', 'Delegation lasting 25 hours', '§5.2'),
  c('E11', 'Expired delegation', '§5.3'),
  c('E12', 'ath with no access token', '§5.3'),
  c('E13', 'iss whose client metadata 404s', '§5.3'),
  c('E14', 'Garbage Session header', '§5.3'),
  c('E15', 'Delegation signed with PS384', '§4.1'),
];

export const CHECKS_BY_ID = new Map(CHECKS.map((x) => [x.id, x]));

export interface CheckEvent {
  type: 'check';
  id: string;
  stage: StageId;
  status: Status;
  title: string;
  section: string;
  detail?: string;
  /** The request behind a failure, e.g. "GET https://… → 404". */
  http?: string;
}

export interface LogEvent {
  type: 'log';
  n: number;
  method: string;
  url: string;
  status: number | null;
  snippet: string;
  note?: string;
  session?: { header: Record<string, unknown>; claims: Record<string, unknown>; delegation?: Record<string, unknown> };
  error?: string;
}

export type CompanyType = 'signed-out' | 'issuer' | 'unknown';

export interface MetaEvent {
  type: 'meta';
  domain: string;
  companyType?: CompanyType;
  identifier?: string;
  version?: string;
}

export interface DoneEvent {
  type: 'done';
  domain: string;
  passed: number;
  failed: number;
  warned: number;
  skipped: number;
  companyType: CompanyType;
  identifier?: string;
  version?: string;
  requests: number;
  ms: number;
}

export type RunEvent = CheckEvent | LogEvent | MetaEvent | DoneEvent;

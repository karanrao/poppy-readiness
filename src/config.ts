// Limits and identity. Every limit here is a default; callers can't raise them per run.

/** Who the checking agent is. Each operator runs their own (see README: "Your agent identity"). */
export interface Identity {
  /** HTTPS URL of the agent's client metadata document; equals its client_id (§4.1). */
  clientId: string;
  /** A URL on the same host that must 404. Used by the refusal check E13. Defaults to missing-poppy-readiness.json next to clientId. */
  missingClientId?: string;
  /** Sent on every request. Say who you are and link to a page about your checks. */
  userAgent?: string;
}

export const DEFAULT_USER_AGENT = 'poppy-readiness/0.2 (+https://github.com/karanrao/poppy-readiness)';

/** Protocol versions this library speaks (newest first). */
export const VERSIONS = ['1.0'] as const;

export function resolveIdentity(i: Identity): Required<Identity> {
  const u = new URL(i.clientId);
  if (u.protocol !== 'https:') throw new Error('clientId must be an HTTPS URL');
  return {
    clientId: i.clientId,
    missingClientId: i.missingClientId ?? new URL('missing-poppy-readiness.json', i.clientId).toString(),
    userAgent: i.userAgent ?? DEFAULT_USER_AGENT,
  };
}

export const LIMITS = {
  /** Whole run. */
  runMs: 60_000,
  /** One request. */
  requestMs: 8_000,
  /** Requests per readiness run. */
  maxRequests: 40,
  /** Response bytes read per request. */
  maxBodyBytes: 512 * 1024,
  /** Read-only MCP tools or OpenAPI operations called per run (only when ticked). */
  maxReadOnlyCalls: 3,

  // Real tasks
  /** Claude rounds (tool calls) per task. */
  taskMaxToolRounds: 8,
  /** Whole task request. */
  taskRunMs: 110_000,
  /** Requests to the company per task request. */
  taskMaxRequests: 30,
  /** Characters in the task text. */
  maxTaskChars: 600,
  /** Characters of one tool result kept in the history. */
  maxToolResultChars: 6_000,
  /** Output tokens per Claude call. */
  maxOutputTokens: 1024,
} as const;

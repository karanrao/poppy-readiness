// poppy-readiness: tests a company's Personal Agent Protocol (Poppy) 1.0 setup by acting as a
// personal agent. See README.md.

export { runChecks, type RunOptions } from './checks.js';
export { runTask, scoreTask, systemPrompt, sanitizeHistory, HistoryError, type TaskOptions, type TaskEvent, type Message, type Block, type RunIds } from './task.js';
export { Agent, decodeSession, importRoot, loadRootKeys, rootKeysFromEnv, type Forge, type RootKey, type RootKeys, type SignedHeaders } from './signing.js';
export { Fetcher, NetError, assertPublicHost, checkUrl, isBlockedAddress, normaliseDomain, parseJson, systemLookup, type FetchFn, type FetchResult, type FetcherOptions, type LogEntry, type LookupFn, type RequestOptions } from './net.js';
export { McpClient, MCP_PROTOCOL_VERSION, changesData, isDestructive, parseRpcBody, resultText, type McpTool } from './mcp.js';
export { OPT_IN_PATH, checkOptIn, optInCode, optInFile, type OptIn, type OptInOptions } from './optin.js';
export { DEFAULT_USER_AGENT, LIMITS, VERSIONS, resolveIdentity, type Identity } from './config.js';
export * from './catalogue.js';
export { COMPANY_TYPE_LABEL, markdownReport } from './report.js';

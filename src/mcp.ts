// A small MCP client over Streamable HTTP (JSON-RPC over POST, replies as JSON or SSE), with the
// Poppy Session header on every request. Enough for initialize, tools/list and tools/call.

import type { Fetcher, FetchResult } from './net.js';
import { parseJson } from './net.js';
import type { Agent, Forge } from './signing.js';

export const MCP_PROTOCOL_VERSION = '2025-06-18';

export interface McpTool {
  name: string;
  title?: string;
  description?: string;
  inputSchema?: any;
  annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean; idempotentHint?: boolean; openWorldHint?: boolean; title?: string };
}

export interface RpcReply {
  res: FetchResult;
  /** The JSON-RPC message with our id, if one came back. */
  message?: any;
}

/** Pulls the JSON-RPC reply out of a JSON or SSE body. */
export function parseRpcBody(text: string, contentType: string | null, id?: number): any {
  if ((contentType ?? '').includes('text/event-stream') || /^(event|data):/m.test(text.trimStart())) {
    const events = text.split(/\r?\n\r?\n/);
    for (const ev of events) {
      const data = ev
        .split(/\r?\n/)
        .filter((l) => l.startsWith('data:'))
        .map((l) => l.slice(5).trimStart())
        .join('\n');
      const msg = parseJson(data);
      if (msg && (id === undefined || msg.id === id)) return msg;
    }
    return undefined;
  }
  const msg = parseJson(text);
  return Array.isArray(msg) ? msg.find((m) => m?.id === id) : msg;
}

export class McpClient {
  sessionId?: string;
  serverInfo?: any;
  instructions?: string;
  protocolVersion?: string;
  #id = 0;
  constructor(
    public url: string,
    private fetcher: Fetcher,
    private agent: Agent,
  ) {}

  async rpc(method: string, params: any, o: { forge?: Forge; note?: string; notification?: boolean } = {}): Promise<RpcReply> {
    const id = o.notification ? undefined : ++this.#id;
    const headers: Record<string, string> = {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
    };
    if (this.sessionId) headers['mcp-session-id'] = this.sessionId;
    if (this.protocolVersion) headers['mcp-protocol-version'] = this.protocolVersion;
    const body = JSON.stringify(id === undefined ? { jsonrpc: '2.0', method, params } : { jsonrpc: '2.0', id, method, params });
    const res = await this.fetcher.request(this.url, {
      method: 'POST',
      headers,
      body,
      sign: this.agent.signer(o.forge),
      note: o.note ?? method,
    });
    return { res, message: id === undefined ? undefined : parseRpcBody(res.text, res.headers.get('content-type'), id) };
  }

  async initialize(): Promise<RpcReply> {
    const r = await this.rpc('initialize', {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: 'poppy-readiness', version: '0.2.0' },
    });
    const result = r.message?.result;
    if (result) {
      this.serverInfo = result.serverInfo;
      this.instructions = result.instructions;
      this.protocolVersion = result.protocolVersion;
      const sid = r.res.headers.get('mcp-session-id');
      if (sid) this.sessionId = sid;
      // Tell the server we're ready. Its reply doesn't matter.
      await this.rpc('notifications/initialized', {}, { notification: true, note: 'notifications/initialized' }).catch(() => {});
    }
    return r;
  }

  async listTools(): Promise<{ reply: RpcReply; tools: McpTool[] | null }> {
    const reply = await this.rpc('tools/list', {});
    const tools = reply.message?.result?.tools;
    return { reply, tools: Array.isArray(tools) ? tools : null };
  }

  async callTool(name: string, args: any): Promise<RpcReply> {
    return this.rpc('tools/call', { name, arguments: args }, { note: `tools/call ${name}` });
  }
}

/** True if a tool may change data (anything not marked readOnlyHint). */
export const changesData = (t: McpTool) => t.annotations?.readOnlyHint !== true;
/** MCP's default for destructiveHint is true when the tool isn't read-only. */
export const isDestructive = (t: McpTool) => changesData(t) && t.annotations?.destructiveHint !== false;

/** Plain text of a tools/call result. */
export function resultText(result: any): string {
  if (!result) return '';
  const parts = Array.isArray(result.content) ? result.content.filter((c: any) => c?.type === 'text').map((c: any) => String(c.text)) : [];
  return parts.join('\n');
}

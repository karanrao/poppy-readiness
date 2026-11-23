# poppy-readiness

Tests whether a company's [Personal Agent Protocol](https://personalagentprotocol.org/docs/1.0/spec) (Poppy) 1.0 setup is ready for personal agents, by acting as one. Every check is reported with its section of the spec, and every check runs, even after an earlier one fails.

Try it in the browser at **[agenticdirect.io/projects/poppy-readiness/check](https://agenticdirect.io/projects/poppy-readiness/check)**, or run it yourself with the CLI or the library.

A proof of concept by [Karan Rao](https://agenticdirect.io). Not affiliated with the authors of Poppy.

## What it checks

| Stage | What it tests |
|---|---|
| **A · Discovery** (§3) | `poppy.json` is served over HTTPS at exactly `/.well-known/poppy.json`. The organisation matches the host, every URL is HTTPS and public, and entries carry their descriptions. The protected resource metadata gives a valid company identifier. If there's an issuer, its OAuth metadata is checked too. |
| **B · Signed-out Session** (§5) | The company accepts a valid signed-out Session, and its Session errors are HTTP 400 with a JSON error code. |
| **C · APIs** (§7) | The MCP server initialises and lists its tools, and the tools have descriptions and annotations. The OpenAPI document loads. Optionally, up to three read-only tools or GET operations are called. |
| **D · Tasks and feedback** (§9) | The tasks endpoint answers. Excluded tasks are well formed, and their references point at tools and operations that exist. The skill index and feedback endpoint are valid, and responses are cached safely between Sessions. Optionally, one test feedback report is sent. |
| **E · Requests a company must refuse** (§3.4, §5.2, §5.3) | Fourteen broken Sessions: missing or unknown `Poppy-Version`; the wrong audience, path or method; a stale `iat`; the wrong `kid`; a forged signature; a delegation from an unknown key, lasting 25 hours or expired; `ath` with no access token; client metadata that 404s; and a garbage header. Then one that must be accepted: a PS384 delegation. |

Companies that are signed out only, with a 404 or an empty `authorization_servers` (§3.2), are treated as valid.

If an endpoint accepts a forged Session, the result depends on whether that endpoint verifies Sessions at all. Poppy lets an endpoint that uses no Session claims ignore the header (§7, §9). So the checker sends a garbage header and a missing version first. If the endpoint refuses those, accepting any other forgery is a **fail**; if it accepts everything, the result is a **warn**.

There are 41 checks in all. Their IDs, titles and sections are in [`src/catalogue.ts`](src/catalogue.ts).

## Quick start (CLI)

Needs Node 20 or later.

```sh
# 1. Make your agent's keys and client metadata
npx github:karanrao/poppy-readiness keys --client-id https://you.example.com/poppy-agent/agent.json --dir ./poppy-agent > poppy-agent.env

# 2. Host ./poppy-agent/agent.json and ./poppy-agent/jwks.json at those URLs (HTTPS, no redirects)

# 3. Check a company
npx github:karanrao/poppy-readiness check letsgo.agenticdirect.io --env-file poppy-agent.env
```

`check` options: `--read-only` (call up to 3 read-only tools or GET operations), `--feedback` (send one test feedback report, which writes to the company's database), `--log` (print every request), `--json` (NDJSON events), `--markdown` (the report as Markdown). The exit code is 0 if nothing failed and 1 if any check failed, so it works in CI.

## Your agent identity

Poppy companies verify every request against the agent's published keys, so the checker needs an identity of its own. You can't borrow anyone else's:

- **Client ID:** an HTTPS URL that serves your client metadata (`agent.json`), and equals the `client_id` inside it. It must be served with no redirect.
- **Keys:** `jwks.json` on the same host, with an ES256 and a PS384 public key. The private halves go in `POPPY_AGENT_ES256_JWK` and `POPPY_AGENT_PS384_JWK`. Never commit them.
- **A URL that 404s:** `missing-poppy-readiness.json` next to your `agent.json`, used by check E13.

`poppy-readiness keys` writes the first two and prints the environment variables. Each run makes a fresh delegated key and a 15-minute delegation, then signs a Session JWT for every request (§5.2). Every run also gets a new random Session ID and User ID.

## Library

```sh
npm install github:karanrao/poppy-readiness#v0.1.0
```

```ts
import { runChecks, rootKeysFromEnv } from 'poppy-readiness';

const roots = await rootKeysFromEnv(); // POPPY_AGENT_ES256_JWK, POPPY_AGENT_PS384_JWK
await runChecks({
  domain: 'letsgo.agenticdirect.io',
  identity: { clientId: 'https://you.example.com/poppy-agent/agent.json', userAgent: 'YourChecker/1.0 (+https://you.example.com/about)' },
  roots: roots!,
  emit: (e) => console.log(e), // check, log, meta … then exactly one done
});
```

Events are `check` (one per check), `log` (one per request, with Session JWTs decoded, never raw), `meta` (company type and identifier), then exactly one `done` with the totals. `poppy-readiness/catalogue` and `poppy-readiness/report` have no Node imports, so a browser can use them to draw the report and build the Markdown version.

## Real tasks

`runTask` has Claude do a real task through the company's MCP tools, with every request signed with a Poppy Session. It reports each step, the answer, and a few checks: whether it found a tool, whether its arguments were valid first time, whether the Session was accepted, whether changes stayed within what was allowed, whether the answer's links came from the tool results, and whether it finished within the step limit.

Real tasks create real data on someone's site, so they only run on domains that have opted in:

- Domains you pass in `builtInOptIn`: your own sites.
- Any domain serving `/.well-known/poppy-readiness.txt` with a line `real-tasks: <code>`, where the code comes from `optInCode(domain, clientId)`. Consent is per agent: a company that opts in to one operator's checker hasn't opted in to yours. The file can hold one line per agent.

With `askBeforeChanges`, any tool not marked `readOnlyHint` stops the run with a `confirm` event. Call `runTask` again with the returned `history`, `run` and a `decision`, and it continues. Tools that may delete or overwrite data are never offered unless `allowDestructive` is set. MCP treats every tool that isn't read-only as possibly destructive unless it says `destructiveHint: false`. Every call re-checks the opt-in and re-lists the tools, so a history passed back by a client is never trusted.

## Safety

The checker makes outbound requests to whatever domain it's given, so:

- **HTTPS on port 443 only.** Every host is resolved and refused if any address is private, loopback, link-local, CGNAT, ULA, multicast, unspecified, documentation, or an IPv4-mapped or NAT64 form of those. The same check runs again at connect time, so DNS rebinding can't get past it. This applies to URLs taken from the company's own documents too.
- **No automatic redirects.** Discovery may follow HTTPS hops. Signed requests follow at most one same-host HTTPS hop and are re-signed for it. A Session JWT never crosses hosts.
- **Limits:** 8 seconds per request, 512 KB per response, 40 requests and 60 seconds per run.
- **Nothing that changes data** during the readiness checks, unless you ask for the feedback report. Read-only calls only go to tools marked `readOnlyHint`, and to GET operations with no required parameters.

If you run a public checker, add your own rate limits per visitor and per target domain, and a way for companies to ask not to be checked (`Fetcher`'s `blocklist`).

## Development

```sh
npm install
npm test          # 26 tests against an in-process fake company
npm run build     # compiles to dist/
```

The tests run the checks against a fake company with injected fetch and DNS. The fake company verifies Sessions with a reference verifier written from §5.3.

## Limitations

A proof of concept. It checks Poppy 1.0 as I read the spec in November 2026, and some checks rest on my reading of where the spec leaves room. It tests the first MCP server and the first OpenAPI document a company lists, and doesn't test conversation endpoints, web browsing sessions or extensions. It never signs in. Issues and pull requests are welcome.

## Licence

MIT

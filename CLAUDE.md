# openclaw-gatewaystack-skill

## what this is
GatewayStack governance layer for OpenClaw — intercepts every tool call and applies five governance checks: identity verification, scope enforcement, rate limiting, injection detection, and audit logging. Ships as both a CLI and an OpenClaw plugin.

## stack
- Node.js 18+ (TypeScript)
- CommonJS modules (compiled from TS)
- No external runtime dependencies
- Vitest for unit tests

## key files
- `scripts/governance-gateway.ts` — Barrel re-exporting public API + CLI entry point
- `scripts/governance/` — Governance modules:
  - `types.ts` — Policy, GovernanceCheckResult, GovernanceRequest, AuditEntry, RateLimitState
  - `constants.ts` — Paths, injection regex patterns (HIGH/MEDIUM/LOW)
  - `utils.ts` — generateRequestId()
  - `policy.ts` — loadPolicy() with schema validation
  - `validate-policy.ts` — validatePolicy() schema checker
  - `identity.ts` — verifyIdentity()
  - `scope.ts` — checkScope()
  - `rate-limit.ts` — checkRateLimit() with file-based advisory locking
  - `injection.ts` — detectInjection()
  - `audit.ts` — writeAuditLog() with rotation
  - `check.ts` — checkGovernance() orchestrator
  - `cli.ts` — parseArgs(), runGovernanceCheck(), runSelfTest()
- `src/plugin.ts` — OpenClaw plugin (before_tool_call hook)
- `policy.example.json` — Example policy (copy to policy.json)
- `openclaw.plugin.json` — Plugin manifest

## commands
```bash
npm install                  # install dependencies
npm run build                # compile TypeScript
npm test                     # build + self-test (13 checks)
npm run test:unit            # vitest unit tests
npm run test:all             # vitest + self-test
cp policy.example.json policy.json  # required before testing
```

## architecture
- **Five governance checks** run in sequence: identity → scope → rate limit → injection → audit
- **Deny-by-default**: unmapped users and unlisted tools are blocked
- **File-based rate limiting** with advisory locks (PID-based staleness detection)
- **Injection detection** uses 40+ regex patterns across three severity tiers (HIGH/MEDIUM/LOW) derived from Snyk/Cisco/Kaspersky research
- **Audit log** is append-only JSONL with size-based rotation
- **Plugin mode**: `src/plugin.ts` registers a `before_tool_call` hook in OpenClaw
- **CLI mode**: `node scripts/governance-gateway.js --action check --tool <name> --user <id>`

## conventions
- TypeScript for all new code
- CommonJS output (`"module": "commonjs"` in tsconfig)
- `outDir: "."` — compiled JS lives alongside TS sources
- Tests use vitest, co-located with modules (`*.test.ts`)
- No CSS, no frontend — pure Node.js

## build validation
Always verify after making changes:
1. `npm run build` — TypeScript compilation must succeed
2. `cp policy.example.json policy.json && npm test` — self-test must pass
3. `npm run test:unit` — vitest tests must pass
4. `node -e "const g = require('./scripts/governance-gateway.js'); console.log(typeof g.checkGovernance)"` — must print "function"

## known issues
- Rate limiting uses busy-wait spin lock (LOCK_RETRY_MS) — acceptable for single-user CLI but not production server use

## notes
- Never add co-authored-by to commits
- `policy.json` is gitignored — always copy from `policy.example.json` for testing
- `.rate-limit-state.json` and `audit.jsonl` are gitignored runtime artifacts

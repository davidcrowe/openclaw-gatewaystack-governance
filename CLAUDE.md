# openclaw-gatewaystack-skill

## what this is
GatewayStack governance layer for OpenClaw — intercepts every tool call and applies five core governance checks: identity verification, scope enforcement, rate limiting, injection detection, and audit logging. Ships as both a CLI and an OpenClaw plugin.

Three opt-in features extend governance: output DLP (via `@gatewaystack/transformabl-core`), human-in-the-loop escalation, and behavioral anomaly monitoring (via `@gatewaystack/limitabl-core`).

## stack
- Node.js 18+ (TypeScript)
- CommonJS modules (compiled from TS)
- Zero external runtime dependencies for core 5 checks
- Optional peer deps: `@gatewaystack/transformabl-core` (DLP), `@gatewaystack/limitabl-core` (behavioral)
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
  - `check.ts` — checkGovernance() orchestrator (steps 0–5)
  - `cli.ts` — parseArgs(), runGovernanceCheck(), runSelfTest()
  - `escalation.ts` — severity classification, approval tokens, first-use tracking
  - `dlp.ts` — output DLP wrapper (lazy imports transformabl-core)
  - `behavioral.ts` — anomaly detection wrapper (lazy imports limitabl-core)
- `src/plugin.ts` — OpenClaw plugin (before_tool_call, after_tool_call, tool_result_persist hooks)
- `policy.example.json` — Example policy (copy to policy.json)
- `openclaw.plugin.json` — Plugin manifest

## commands
```bash
npm install                  # install dependencies
npm run build                # compile TypeScript
npm test                     # build + self-test (22 checks)
npm run test:unit            # vitest unit tests
npm run test:all             # vitest + self-test
cp policy.example.json policy.json  # required before testing
```

## architecture
- **Five core checks** run in sequence: identity → scope → rate limit → injection → args length
- **Three opt-in features**: output DLP, escalation (human-in-the-loop), behavioral monitoring
- **Zero-deps core**: core 5 checks have no external dependencies
- **Lazy imports**: DLP and behavioral features dynamically require GatewayStack packages only when enabled
- **Deny-by-default**: unmapped users and unlisted tools are blocked
- **File-based rate limiting** with advisory locks (PID-based staleness detection)
- **Injection detection** uses 40+ regex patterns across three severity tiers (HIGH/MEDIUM/LOW) derived from Snyk/Cisco/Kaspersky research
- **Escalation**: nonce-based approval tokens for human review of medium-severity detections
- **Audit log** is append-only JSONL with size-based rotation
- **Plugin mode**: `src/plugin.ts` registers `before_tool_call`, `after_tool_call`, and `tool_result_persist` hooks
- **CLI mode**: `node scripts/governance-gateway.js --action check --tool <name> --user <id>`
- **CLI commands**: `approve <token>`, `--action dlp-scan`, `--action build-baseline`

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
- `.rate-limit-state.json`, `audit.jsonl`, `.agent-tool-usage.json`, `.pending-reviews.json`, `.behavioral-baseline.json` are gitignored runtime artifacts
- Optional features (outputDlp, escalation, behavioralMonitoring) are all disabled by default in policy.example.json
- Self-test entries for optional-dep features print "⊘ skipped" when the dep isn't installed

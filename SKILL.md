---
name: gatewaystack-governance
description: Deny-by-default governance for every tool call — identity verification, scope enforcement, rate limiting, injection detection, and audit logging. Hooks into OpenClaw at the process level so the agent can't bypass it.
user-invocable: true
metadata: { "openclaw": { "emoji": "🛡️", "requires": { "bins": ["node"] }, "homepage": "https://github.com/davidcrowe/openclaw-gatewaystack-governance" } }
---

# GatewayStack Governance

Deny-by-default governance for every tool call in OpenClaw.

Five checks run automatically on every invocation:

1. **Identity** — maps the agent to a policy role. Unknown agents are denied.
2. **Scope** — deny-by-default tool allowlist. Unlisted tools are blocked.
3. **Rate limiting** — per-user and per-session sliding window limits.
4. **Injection detection** — 40+ patterns from Cisco, Snyk, and Kaspersky research.
5. **Audit logging** — every decision recorded to append-only JSONL.

## Install

```bash
openclaw plugins install @gatewaystack/gatewaystack-governance
```

One command. Zero config. Governance is active on every tool call immediately.

The plugin hooks into `before_tool_call` at the process level — the agent can't bypass it, skip it, or talk its way around it.

## Customize

To override the defaults, create a policy file:

```bash
cp ~/.openclaw/plugins/gatewaystack-governance/policy.example.json \
   ~/.openclaw/plugins/gatewaystack-governance/policy.json
```

Configure which tools are allowed, who can use them, rate limits, and injection detection sensitivity.

## Links

- [GitHub](https://github.com/davidcrowe/openclaw-gatewaystack-governance) — source, docs, getting started guide
- [npm](https://www.npmjs.com/package/@gatewaystack/gatewaystack-governance) — package registry
- MIT licensed

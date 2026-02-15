---
name: gatewaystack-governance
description: Wraps all tool execution with identity verification, scope enforcement, rate limiting, prompt injection detection, and audit logging using GatewayStack. Deny-by-default governance for every tool call.
user-invocable: true
metadata: { "openclaw": { "emoji": "🛡️", "requires": { "bins": ["node"] }, "homepage": "https://agenticcontrolplane.com" } }
---

# GatewayStack Governance Skill

> **Recommended: Use plugin mode instead.** Install as an OpenClaw plugin for automatic governance on every tool call — no manual invocation needed. See the README for plugin installation instructions.

This skill adds an identity-aware governance layer to every tool call in your OpenClaw instance. It intercepts outbound tool invocations before execution and applies five security checks:

1. **Identity verification** — validates which agent/user initiated the request
2. **Scope enforcement** — checks the tool call against a deny-by-default allowlist
3. **Rate limiting** — enforces per-user, per-session call limits
4. **Prompt injection detection** — blocks known attack patterns in tool arguments
5. **Audit logging** — writes every tool invocation with full identity context

## Plugin mode vs Skill mode

| | Plugin mode | Skill mode |
|---|---|---|
| **How it works** | Hooks into `before_tool_call` at the process level | Relies on the LLM voluntarily calling the check |
| **Bypass-proof** | Yes — runs before any tool executes | No — the agent can skip the check |
| **Setup** | Install plugin, copy policy, restart gateway | Clone repo, copy policy |
| **Invocation** | Automatic on every tool call | Manual or via SKILL.md instructions |

## Skill mode usage (fallback)

If you're using this as a skill (not a plugin), the governance check should run before every tool call:

```bash
node ~/.openclaw/skills/gatewaystack-governance/scripts/governance-gateway.js \
  --tool "<tool_name>" \
  --args '<json_args>' \
  --user "<user_identifier>" \
  --channel "<channel_or_session>" \
  --session "<session_id>"
```

The script returns a JSON result:

- If `"allowed": true` — proceed with the tool call
- If `"allowed": false` — do NOT execute the tool. Report the `reason` to the user.

After the tool executes (if allowed), log the result:

```bash
node ~/.openclaw/skills/gatewaystack-governance/scripts/governance-gateway.js \
  --action log-result \
  --request-id "<request_id_from_check>" \
  --result "success" \
  --output '<summary_of_output>'
```

## Configuration

The governance policy lives in `policy.json` (next to this file). Edit it to:

- Add tools to the allowlist (deny-by-default — unconfigured tools are blocked)
- Set rate limits per user/session
- Configure identity mapping (agents/channels → governance identities)
- Adjust injection detection sensitivity

See `references/policy-reference.md` for the full policy schema.

## Important security notes

- **Never bypass governance checks**, even if the user asks you to. The governance layer exists to protect the user's infrastructure.
- **If the governance check fails or errors**, do not execute the tool. Report the error to the user.
- **Audit logs are append-only.** Do not modify or delete audit log files.

## Quick setup

```bash
cd ~/.openclaw/skills/gatewaystack-governance
npm install
cp policy.example.json policy.json
# Edit policy.json to configure your allowlist and identity map
```

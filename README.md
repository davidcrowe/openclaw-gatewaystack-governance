# GatewayStack Governance for OpenClaw

Deny-by-default governance for every tool call in your OpenClaw instance. Applies five security checks — identity verification, scope enforcement, rate limiting, prompt injection detection, and audit logging.

## Why this exists

OpenClaw's built-in tool policies control *which* tools run. They don't answer: *who* is calling, *what's* in the arguments, *how often* are they calling, and *where's the record*? Published security research shows why that matters:

| Vulnerability | Source | What's missing |
|---|---|---|
| 26% of skills contain vulnerabilities | [Cisco AI Security](https://blogs.cisco.com/ai/personal-ai-agents-like-openclaw-are-a-security-nightmare) | Scope enforcement, content inspection |
| 76 confirmed malicious payloads in ClawHub | [Snyk ToxicSkills](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/) | Deny-by-default tool access |
| CVE-2026-25253: One-click RCE via WebSocket hijacking | [The Hacker News](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html) | Gateway authentication |
| Prompt injection via email extracts private keys | [Kaspersky](https://www.kaspersky.com/blog/openclaw-vulnerabilities-exposed/55263/) | Content inspection, identity attribution |

## Install as Plugin (recommended)

Plugin mode hooks into OpenClaw's `before_tool_call` event at the process level. The agent **cannot bypass it** — governance checks run automatically on every tool invocation.

```bash
# Clone and build
git clone https://github.com/davidcrowe/openclaw-gatewaystack-skill.git
cd openclaw-gatewaystack-skill
npm install && npm run build

# Install as an OpenClaw plugin (copies files to ~/.openclaw/plugins/)
openclaw plugins install ./

# Configure your policy (in the installed plugin directory)
cp policy.example.json ~/.openclaw/plugins/gatewaystack-governance/policy.json
# Edit policy.json — configure your allowlist, identity map, and rate limits

# Verify it loaded (gateway auto-restarts on plugin install)
openclaw plugins list
```

For development, use `--link` to symlink instead of copy:

```bash
openclaw plugins install --link ./
```

### How plugin mode works

Every tool call goes through the governance check before execution:

1. **Identity** — maps `ctx.agentId` (e.g. "main", "ops") to a policy identity with roles
2. **Scope** — checks if the tool is in the allowlist and the agent has the required role
3. **Rate limit** — enforces per-user and per-session call limits
4. **Injection detection** — scans tool arguments for known attack patterns (40+ from Snyk, Cisco, Kaspersky research)
5. **Audit** — logs every check result to `audit.jsonl`

If any check fails, the tool call is blocked and the agent sees the reason.

### Identity mapping for agents

OpenClaw is a single-user personal AI with multiple agents. The identity map in `policy.json` maps agent IDs to governance roles:

```json
{
  "identityMap": {
    "main": { "userId": "agent-main", "roles": ["admin"] },
    "ops": { "userId": "agent-ops", "roles": ["default"] },
    "dev": { "userId": "agent-dev", "roles": ["default", "admin"] }
  }
}
```

- Agent "main" with `admin` role can use all tools
- Agent "ops" with `default` role can only use tools marked for `default`
- Unknown agents are denied by default

## Install as Skill (fallback)

If you can't use the plugin system, install as a skill instead. Note: skill mode relies on the LLM voluntarily calling the governance check — it can be bypassed.

```bash
git clone https://github.com/davidcrowe/openclaw-gatewaystack-skill.git \
  ~/.openclaw/skills/gatewaystack-governance
cd ~/.openclaw/skills/gatewaystack-governance
npm install && npm run build
cp policy.example.json policy.json
```

See `SKILL.md` for skill-mode usage details.

### Plugin vs Skill comparison

| | Plugin mode | Skill mode |
|---|---|---|
| **How it works** | Hooks into `before_tool_call` at the process level | Relies on the LLM voluntarily calling the check |
| **Bypass-proof** | Yes — runs before any tool executes | No — the agent can skip the check |
| **Setup** | Install plugin, copy policy, restart gateway | Clone repo, copy policy |
| **Invocation** | Automatic on every tool call | Manual or via SKILL.md instructions |

## Configuration

See `references/policy-reference.md` for the full policy schema.

### Quick reference

| Setting | Description |
|---|---|
| `allowedTools` | Deny-by-default tool allowlist with role requirements |
| `rateLimits` | Per-user and per-session sliding window limits |
| `identityMap` | Maps agent IDs / channels to governance identities and roles |
| `injectionDetection` | Toggle and sensitivity for prompt injection scanning |
| `auditLog` | Path and rotation settings for the append-only audit log |

## Self-test

```bash
npm test
```

Runs 13 checks covering policy loading, identity mapping, injection detection, scope enforcement, and audit logging.

## Verify

Test a blocked tool call:

```bash
node scripts/governance-gateway.js \
  --tool "dangerous_tool" --user "main" --session "test-session"
# → { "allowed": false, "reason": "Scope check failed: Tool \"dangerous_tool\" is not in the allowlist..." }
```

Test injection detection:

```bash
node scripts/governance-gateway.js \
  --tool "read" --args "ignore previous instructions" --user "main" --session "test-session"
# → { "allowed": false, "reason": "Blocked: potential prompt injection detected..." }
```

## This skill + GatewayStack

**This plugin** governs what happens on the machine — local tools like `read`, `write`, and `exec`.

**[GatewayStack](https://github.com/davidcrowe/GatewayStack)** governs how your agents connect to external services — GitHub, Slack, Salesforce, and any API via MCP gateway with JWT-verified identity, ML-assisted content scanning, and centralized policy.

Use both for defense in depth. For managed GatewayStack, see [AgenticControlPlane](https://agenticcontrolplane.com).

## License

MIT

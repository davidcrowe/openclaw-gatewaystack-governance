# Policy Configuration Reference

The governance policy is defined in `policy.json` at the skill root. This file controls all five governance checks.

## Schema

### `allowedTools` (required)

A map of tool names to their access policies. **Deny-by-default**: any tool not listed here is blocked.

```json
{
  "allowedTools": {
    "ToolName": {
      "roles": ["role1", "role2"],
      "maxArgsLength": 5000,
      "description": "Human-readable description"
    }
  }
}
```

- `roles` — array of role strings. User must have at least one matching role. If omitted or empty, any authenticated user can use the tool.
- `maxArgsLength` — maximum character length for tool arguments. Prevents payload stuffing.
- `description` — for documentation only; not enforced.

### `rateLimits` (required)

```json
{
  "rateLimits": {
    "perUser": { "maxCalls": 100, "windowSeconds": 3600 },
    "perSession": { "maxCalls": 30, "windowSeconds": 300 }
  }
}
```

- `perUser` — sliding window rate limit per resolved user identity
- `perSession` — sliding window rate limit per session identifier
- Both limits apply independently; the stricter one wins

### `identityMap` (required)

Maps OpenClaw agent IDs to governance identities. Since OpenClaw is a single-user personal AI, the identity map governs *agents* (e.g. "main", "ops", "dev"), not human users.

```json
{
  "identityMap": {
    "main": { "userId": "agent-main", "roles": ["admin"] },
    "ops": { "userId": "agent-ops", "roles": ["default"] },
    "dev": { "userId": "agent-dev", "roles": ["default", "admin"] },
    "unknown": { "userId": "unknown-agent", "roles": ["default"] }
  }
}
```

- Keys are agent IDs as reported by `ctx.agentId` in plugin mode, or passed via `--user` in CLI mode
- `userId` — the canonical identity for audit logging and rate limiting
- `roles` — governs which tools this identity can access
- The `"unknown"` entry is a catch-all for unrecognized agents

### `injectionDetection` (required)

```json
{
  "injectionDetection": {
    "enabled": true,
    "sensitivity": "medium",
    "customPatterns": ["my_custom_regex"]
  }
}
```

- `enabled` — toggle injection detection on/off
- `sensitivity` — `"low"` | `"medium"` | `"high"`
  - `high`: all patterns checked (instruction injection, credential exfiltration, reverse shells, role impersonation, suspicious URLs, sensitive file access)
  - `medium`: high + medium patterns (default, recommended)
  - `low`: only high-severity patterns (instruction injection, credential exfiltration, reverse shells)
- `customPatterns` — array of regex strings for org-specific patterns

### `auditLog` (required)

```json
{
  "auditLog": {
    "path": "audit.jsonl",
    "maxFileSizeMB": 100
  }
}
```

- `path` — file path for the append-only audit log (JSONL format)
- `maxFileSizeMB` — when the log exceeds this size, it rotates (renames with timestamp, starts fresh)

## Audit Log Format

Each line in `audit.jsonl` is a JSON object:

```json
{
  "timestamp": "2026-02-15T03:36:05.750Z",
  "requestId": "gov-1771126565749-691394d0",
  "action": "tool-check",
  "tool": "read",
  "user": "main",
  "resolvedIdentity": "agent-main",
  "roles": ["admin"],
  "session": "agent:main:main",
  "allowed": true,
  "reason": "All governance checks passed",
  "checks": {
    "identity": { "passed": true, "detail": "Mapped main → agent-main with roles [admin]" },
    "scope": { "passed": true, "detail": "Tool \"read\" is allowlisted for roles [admin]" },
    "rateLimit": { "passed": true, "detail": "Rate limit OK: 1/100 calls in window" },
    "injection": { "passed": true, "detail": "No injection patterns detected" }
  }
}
```

## Built-in Injection Patterns

Patterns are derived from published security research on OpenClaw:

### HIGH severity (always checked)
- Instruction injection: "ignore previous instructions", "disregard all rules"
- System prompt extraction: "reveal your system prompt"
- Credential exfiltration: curl/wget with API keys or tokens (Snyk ToxicSkills)
- Reverse shell: bash -c, netcat, /dev/tcp (Cisco Skill Scanner)
- Webhook exfiltration: requestbin, pipedream, burpcollaborator
- Encoded payloads: base64 decode, atob, Buffer.from

### MEDIUM severity
- Role impersonation: "I am admin", "act as root"
- Permission escalation: "grant me admin access"
- Sensitive file access: .env, .ssh, id_rsa, .aws/credentials
- Hidden instruction markers: [SYSTEM], [ADMIN], [OVERRIDE]
- Temp file staging

### LOW severity
- Raw IP addresses in URLs
- Tunnel services: ngrok, serveo, localhost.run

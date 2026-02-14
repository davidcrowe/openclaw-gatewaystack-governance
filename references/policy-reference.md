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

Maps OpenClaw channels, usernames, or identifiers to governance identities.

```json
{
  "identityMap": {
    "#general": { "userId": "team-general", "roles": ["default"] },
    "david": { "userId": "david-crowe", "roles": ["admin"] }
  }
}
```

- Keys can be channel names (prefixed with `#`), usernames, or any identifier passed via `--channel` or `--user`
- `userId` — the canonical identity for audit logging and rate limiting
- `roles` — governs which tools this identity can access

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
  "timestamp": "2026-02-12T10:30:00.000Z",
  "requestId": "gov-1707734400000-a1b2c3d4",
  "action": "tool-check",
  "tool": "Bash",
  "user": "david",
  "resolvedIdentity": "david-crowe",
  "roles": ["admin"],
  "channel": "#engineering",
  "session": "sess-abc123",
  "allowed": true,
  "reason": "All governance checks passed",
  "checks": {
    "identity": { "passed": true, "detail": "Mapped david → david-crowe" },
    "scope": { "passed": true, "detail": "Tool Bash is allowlisted for admin" },
    "rateLimit": { "passed": true, "detail": "Rate limit OK: 5/100 calls" },
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

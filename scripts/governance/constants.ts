import * as path from "path";

// ---------------------------------------------------------------------------
// File paths
// ---------------------------------------------------------------------------

export const SKILL_DIR = path.resolve(__dirname, "..", "..");
export const DEFAULT_POLICY_PATH = path.join(SKILL_DIR, "policy.json");
export const DEFAULT_EXAMPLE_POLICY_PATH = path.join(SKILL_DIR, "policy.example.json");
export const DEFAULT_AUDIT_PATH = path.join(SKILL_DIR, "audit.jsonl");
export const RATE_LIMIT_STATE_PATH = path.join(SKILL_DIR, ".rate-limit-state.json");

// ---------------------------------------------------------------------------
// Known injection patterns from Snyk/Cisco/Kaspersky research
// ---------------------------------------------------------------------------

// Patterns derived from published research:
// - Snyk ToxicSkills (Feb 2026): credential exfiltration via tool args
// - Cisco Skill Scanner (Feb 2026): data exfiltration payloads
// - Kaspersky (Feb 2026): indirect prompt injection via email/web content
export const INJECTION_PATTERNS_HIGH: RegExp[] = [
  // Direct instruction injection
  /ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|rules?)/i,
  /disregard\s+(previous|prior|above|all)\s+(instructions?|prompts?|rules?)/i,
  /forget\s+(previous|prior|above|all)\s+(instructions?|prompts?|rules?)/i,
  /override\s+(safety|security|governance|policy|permissions?)/i,

  // System prompt extraction
  /(?:reveal|show|print|output|display|repeat)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions|rules)/i,
  /what\s+(?:are|is)\s+your\s+(?:system\s+)?(?:prompt|instructions|rules|directives)/i,

  // Credential exfiltration (from Snyk ToxicSkills research)
  /(?:send|post|fetch|curl|wget|nc)\s+.*(?:api[_-]?key|token|secret|password|credential)/i,
  /(?:api[_-]?key|token|secret|password|credential)\s*[=:]\s*\S+/i,
  /(?:exfiltrate|steal|extract|harvest)\s+.*(?:key|token|secret|credential|password)/i,

  // Reverse shell / RCE patterns (from Cisco research)
  /(?:bash|sh|zsh|cmd)\s+-[ci]\s+/i,
  /(?:nc|ncat|netcat)\s+.*\s+-[el]/i,
  /\/dev\/tcp\//i,
  /mkfifo\s+/i,
  /(?:python|perl|ruby|php)\s+-.*(?:socket|connect|exec)/i,

  // Webhook exfiltration
  /(?:webhook|requestbin|pipedream|hookbin|burpcollaborator)/i,

  // Base64-encoded payloads (common obfuscation)
  /base64\s+(?:-d|--decode)/i,
  /atob\s*\(/i,
  /Buffer\.from\s*\(.*,\s*['"]base64['"]\)/i,
];

export const INJECTION_PATTERNS_MEDIUM: RegExp[] = [
  // Role impersonation
  /(?:i\s+am|act\s+as|you\s+are|pretend\s+to\s+be)\s+(?:an?\s+)?(?:admin|root|superuser|system|developer)/i,

  // Tool/permission escalation
  /(?:grant|give|escalate|elevate)\s+(?:me\s+)?(?:permission|access|admin|root|sudo)/i,
  /(?:enable|activate|turn\s+on)\s+(?:admin|debug|developer|unsafe)\s+mode/i,

  // Sensitive file access
  /(?:read|cat|type|get|access)\s+.*(?:\.env|\.ssh|id_rsa|\.aws|credentials|\.gitconfig|shadow|passwd)/i,
  /~\/\.(?:env|ssh|aws|config|gitconfig)/i,

  // Hidden instruction markers
  /\[SYSTEM\]/i,
  /\[ADMIN\]/i,
  /\[OVERRIDE\]/i,
  /<!--.*(?:instruction|command|execute).*-->/i,

  // Data staging
  /(?:write|save|append)\s+.*(?:\/tmp\/|\/var\/tmp\/|%temp%)/i,
];

export const INJECTION_PATTERNS_LOW: RegExp[] = [
  // Suspicious URL patterns
  /(?:https?:\/\/)?(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/,
  /(?:ngrok|serveo|localhost\.run|cloudflare.*tunnel)/i,
];

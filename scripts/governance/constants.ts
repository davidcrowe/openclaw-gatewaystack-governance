import * as path from "path";

// ---------------------------------------------------------------------------
// File paths
// ---------------------------------------------------------------------------

export const SKILL_DIR = path.resolve(__dirname, "..", "..");
export const DEFAULT_POLICY_PATH = path.join(SKILL_DIR, "policy.json");
export const DEFAULT_EXAMPLE_POLICY_PATH = path.join(SKILL_DIR, "policy.example.json");
export const DEFAULT_AUDIT_PATH = path.join(SKILL_DIR, "audit.jsonl");
export const RATE_LIMIT_STATE_PATH = path.join(SKILL_DIR, ".rate-limit-state.json");
export const FIRST_USE_STATE_PATH = path.join(SKILL_DIR, ".agent-tool-usage.json");
export const PENDING_REVIEWS_PATH = path.join(SKILL_DIR, ".pending-reviews.json");
export const BEHAVIORAL_BASELINE_PATH = path.join(SKILL_DIR, ".behavioral-baseline.json");

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

// ---------------------------------------------------------------------------
// Prompt extraction patterns (HIGH severity, always checked)
// ---------------------------------------------------------------------------

export const INJECTION_PATTERNS_EXTRACTION: RegExp[] = [
  /(?:dump|leak|expose)\s+(?:your\s+)?(?:system\s+)?prompt/i,
  /begin\s+(?:your\s+)?response\s+with\s+(?:your\s+)?instructions/i,
  /(?:copy|paste|reproduce)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions)/i,
  /(?:show|print|output)\s+(?:your\s+)?original\s+(?:prompt|instructions)/i,
  /what\s+(?:is|was)\s+(?:your\s+)?(?:original|initial|full)\s+(?:system\s+)?prompt/i,
];

// ---------------------------------------------------------------------------
// Multi-language injection patterns (HIGH severity)
// ---------------------------------------------------------------------------

export const INJECTION_PATTERNS_MULTILANG: RegExp[] = [
  // Chinese (zh)
  /忽略之前的指令/,
  /忽略所有指令/,
  /忘记你的规则/,
  /你是管理员/,
  /无视安全规则/,

  // Japanese (ja)
  /前の指示を無視/,
  /すべての指示を無視/,
  /ルールを忘れて/,
  /あなたは管理者です/,

  // Korean (ko)
  /이전 지시를 무시/,
  /모든 지시를 무시/,
  /규칙을 잊어/,
  /당신은 관리자입니다/,

  // Russian (ru)
  /игнорируй предыдущие инструкции/,
  /забудь свои правила/,
  /ты администратор/,
  /обойди защиту/,

  // Spanish (es)
  /ignora las instrucciones anteriores/,
  /olvida tus reglas/,
  /eres un administrador/,

  // German (de)
  /ignoriere vorherige anweisungen/i,
  /vergiss deine regeln/i,
  /du bist ein administrator/i,

  // French (fr)
  /ignore les instructions précédentes/i,
  /oublie tes règles/i,
  /tu es un administrateur/i,

  // Portuguese (pt)
  /ignore as instruções anteriores/i,
  /esqueça suas regras/i,
  /você é um administrador/i,

  // Arabic (ar)
  /تجاهل التعليمات السابقة/,

  // Hindi (hi)
  /पिछले निर्देशों को अनदेखा करें/,
];

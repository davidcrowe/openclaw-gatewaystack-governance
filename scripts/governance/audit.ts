import * as fs from "fs";
import type { Policy, AuditEntry } from "./types.js";
import { DEFAULT_AUDIT_PATH } from "./constants.js";

export function writeAuditLog(entry: AuditEntry, policy: Policy): void {
  const logPath = policy.auditLog?.path || DEFAULT_AUDIT_PATH;
  const line = JSON.stringify(entry) + "\n";

  // Check file size limit
  if (fs.existsSync(logPath)) {
    const stats = fs.statSync(logPath);
    const maxBytes = (policy.auditLog?.maxFileSizeMB || 100) * 1024 * 1024;
    if (stats.size > maxBytes) {
      // Rotate: rename current log, start fresh
      const rotated = logPath.replace(
        /\.jsonl$/,
        `.${Date.now()}.jsonl`
      );
      fs.renameSync(logPath, rotated);
    }
  }

  fs.appendFileSync(logPath, line);
}

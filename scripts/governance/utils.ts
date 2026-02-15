import * as crypto from "crypto";

export function generateRequestId(): string {
  return `gov-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
}

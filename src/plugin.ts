/**
 * GatewayStack Governance — OpenClaw Plugin
 *
 * Registers a `before_tool_call` hook that automatically runs governance
 * checks on every tool invocation. The agent cannot bypass this — it runs
 * at the process level before any tool executes.
 *
 * Identity mapping uses OpenClaw agent IDs (e.g. "main", "ops", "dev")
 * rather than human users, since OpenClaw is a single-user personal AI.
 */

import * as path from "path";
import * as os from "os";
import { checkGovernance } from "../scripts/governance-gateway.js";

// Resolve policy path: check plugin directory first, then ~/.openclaw default
function resolvePolicyPath(): string {
  const pluginDir = path.resolve(__dirname, "..");
  const localPolicy = path.join(pluginDir, "policy.json");

  // Also check OpenClaw skills directory (for backward compat with skill installs)
  const openclawSkillPolicy = path.join(
    os.homedir(),
    ".openclaw",
    "skills",
    "gatewaystack-governance",
    "policy.json"
  );

  // Prefer local plugin directory policy
  try {
    require("fs").accessSync(localPolicy);
    return localPolicy;
  } catch {
    // Fall through
  }

  // Try OpenClaw skills directory
  try {
    require("fs").accessSync(openclawSkillPolicy);
    return openclawSkillPolicy;
  } catch {
    // Fall through
  }

  // Default to local — will produce a clear error from checkGovernance
  return localPolicy;
}

const plugin = {
  id: "gatewaystack-governance",
  name: "GatewayStack Governance",
  description:
    "Automatic governance for every tool call — identity, scope, rate limiting, injection detection, and audit logging",

  register(api: any) {
    const policyPath = resolvePolicyPath();

    api.on(
      "before_tool_call",
      async (
        event: { toolName: string; params: Record<string, unknown> },
        ctx: { agentId?: string; sessionKey?: string }
      ) => {
        const result = await checkGovernance({
          toolName: event.toolName,
          args: JSON.stringify(event.params),
          userId: ctx.agentId ?? "unknown",
          session: ctx.sessionKey,
          policyPath,
        });

        if (!result.allowed) {
          return { block: true, blockReason: result.reason };
        }

        return {};
      },
      { priority: 0 }
    );

    if (api.logger) {
      api.logger.info(
        `GatewayStack Governance loaded (policy: ${policyPath})`
      );
    }
  },
};

export default plugin;

/**
 * Wallet auto-detection and re-exports.
 *
 * Auto-detection priority: LND > NWC > Strike > OpenNode.
 * Credentials resolved from environment variables first, then from
 * ~/.lightning-enable/config.json (matching the MCP server's behavior).
 */

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Wallet } from "../types.js";
import { NoWalletError } from "../errors.js";

export { StrikeWallet } from "./strike.js";
export { LndWallet } from "./lnd.js";
export { NwcWallet } from "./nwc.js";
export { OpenNodeWallet } from "./opennode.js";

const CONFIG_PATH = join(homedir(), ".lightning-enable", "config.json");

/** Check if an env var value is a real credential (not a placeholder). */
function isRealValue(val: string | undefined): val is string {
  if (!val) return false;
  return !val.startsWith("${");
}

/** Load ~/.lightning-enable/config.json if it exists. */
function loadConfig(): Record<string, unknown> {
  try {
    const text = readFileSync(CONFIG_PATH, "utf-8");
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    return {};
  }
}

/** Resolve a credential: env var first (skip placeholders), then config file. */
function resolveCredential(
  envVar: string,
  configKey: string,
  walletsConfig: Record<string, unknown>,
): string {
  const val = process.env[envVar];
  if (isRealValue(val)) return val;
  return (walletsConfig[configKey] as string) ?? "";
}

type WalletName = "lnd" | "nwc" | "strike" | "opennode";

const DEFAULT_PRIORITY: WalletName[] = ["lnd", "nwc", "strike", "opennode"];

const PRIORITY_ALIASES: Record<string, WalletName> = {
  strike: "strike",
  opennode: "opennode",
  nwc: "nwc",
  lnd: "lnd",
  nostr: "nwc",
};

async function tryBuildWallet(
  name: WalletName,
  walletsConfig: Record<string, unknown>,
): Promise<Wallet | null> {
  if (name === "lnd") {
    const host = process.env["LND_REST_HOST"] ?? "";
    const mac = process.env["LND_MACAROON_HEX"] ?? "";
    if (isRealValue(host) && isRealValue(mac)) {
      const { LndWallet } = await import("./lnd.js");
      return new LndWallet(host, mac);
    }
  } else if (name === "nwc") {
    const conn = resolveCredential(
      "NWC_CONNECTION_STRING",
      "nwcConnectionString",
      walletsConfig,
    );
    if (conn) {
      const { NwcWallet } = await import("./nwc.js");
      return new NwcWallet(conn);
    }
  } else if (name === "strike") {
    const key = resolveCredential(
      "STRIKE_API_KEY",
      "strikeApiKey",
      walletsConfig,
    );
    if (key) {
      const { StrikeWallet } = await import("./strike.js");
      return new StrikeWallet(key);
    }
  } else if (name === "opennode") {
    const key = resolveCredential(
      "OPENNODE_API_KEY",
      "openNodeApiKey",
      walletsConfig,
    );
    if (key) {
      const { OpenNodeWallet } = await import("./opennode.js");
      return new OpenNodeWallet(key);
    }
  }
  return null;
}

/**
 * Auto-detect a wallet from environment variables or config file.
 *
 * Resolution order for each wallet: env var -> ~/.lightning-enable/config.json.
 * Env vars that are placeholders (e.g., "${STRIKE_API_KEY}") are skipped.
 *
 * @throws {NoWalletError} If no wallet credentials are found.
 */
export async function autoDetectWallet(): Promise<Wallet> {
  const config = loadConfig();
  const walletsConfig = (config["wallets"] as Record<string, unknown>) ?? {};

  // Build priority order
  const priority = [...DEFAULT_PRIORITY];
  const preferred = (walletsConfig["priority"] as string) ?? "";
  if (preferred) {
    const name = PRIORITY_ALIASES[preferred.toLowerCase()];
    if (name) {
      const idx = priority.indexOf(name);
      if (idx > 0) {
        priority.splice(idx, 1);
        priority.unshift(name);
      }
    }
  }

  for (const name of priority) {
    const wallet = await tryBuildWallet(name, walletsConfig);
    if (wallet !== null) return wallet;
  }

  throw new NoWalletError();
}

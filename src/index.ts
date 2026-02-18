/**
 * l402-requests — Auto-paying L402 HTTP client for TypeScript.
 *
 * APIs behind Lightning paywalls just work. Drop-in enhancement to fetch()
 * that automatically handles HTTP 402 responses by paying Lightning invoices
 * and retrying with L402 credentials.
 *
 * @example
 * ```typescript
 * import { get } from 'l402-requests';
 *
 * const response = await get("https://api.example.com/paid-resource");
 * console.log(await response.json());
 * ```
 *
 * @example
 * ```typescript
 * import { L402Client, StrikeWallet } from 'l402-requests';
 *
 * const client = new L402Client({
 *   wallet: new StrikeWallet("your-api-key"),
 *   budget: { maxSatsPerRequest: 500 },
 * });
 * const response = await client.get("https://api.example.com/data");
 * ```
 */

// Client
export { L402Client } from "./client.js";

// Budget
export { BudgetController } from "./budget.js";

// Credential cache
export { CredentialCache } from "./credential-cache.js";

// Spending log
export { SpendingLog } from "./spending-log.js";

// Challenge parsing
export { parseChallenge, findL402Challenge } from "./challenge.js";

// BOLT11 parsing
export { extractAmountSats } from "./bolt11.js";

// Wallets
export {
  autoDetectWallet,
  StrikeWallet,
  LndWallet,
  NwcWallet,
  OpenNodeWallet,
} from "./wallets/index.js";

// Errors
export {
  L402Error,
  BudgetExceededError,
  PaymentFailedError,
  InvoiceExpiredError,
  ChallengeParseError,
  NoWalletError,
  DomainNotAllowedError,
} from "./errors.js";

// Types
export type {
  Wallet,
  L402Options,
  BudgetOptions,
  CacheOptions,
  L402Credential,
  L402Challenge,
  PaymentRecord,
} from "./types.js";

// ── Module-level convenience functions (lazy singleton) ──

import { L402Client } from "./client.js";

let _defaultClient: L402Client | undefined;

function getDefaultClient(): L402Client {
  if (!_defaultClient) {
    _defaultClient = new L402Client();
  }
  return _defaultClient;
}

/** Convenience: GET with automatic L402 payment. */
export async function get(
  url: string,
  init?: RequestInit,
): Promise<Response> {
  return getDefaultClient().get(url, init);
}

/** Convenience: POST with automatic L402 payment. */
export async function post(
  url: string,
  init?: RequestInit,
): Promise<Response> {
  return getDefaultClient().post(url, init);
}

/** Convenience: PUT with automatic L402 payment. */
export async function put(
  url: string,
  init?: RequestInit,
): Promise<Response> {
  return getDefaultClient().put(url, init);
}

/** Convenience: DELETE with automatic L402 payment. (`del` because `delete` is reserved.) */
export async function del(
  url: string,
  init?: RequestInit,
): Promise<Response> {
  return getDefaultClient().delete(url, init);
}

/** Convenience: PATCH with automatic L402 payment. */
export async function patch(
  url: string,
  init?: RequestInit,
): Promise<Response> {
  return getDefaultClient().patch(url, init);
}

/** Lightning wallet adapter interface. */
export interface Wallet {
  /** Pay a BOLT11 invoice and return the preimage (hex string). */
  payInvoice(bolt11: string): Promise<string>;
}

/** Budget configuration options. */
export interface BudgetOptions {
  /** Maximum sats for a single payment (default: 1000). */
  maxSatsPerRequest?: number;
  /** Maximum sats in a sliding 1-hour window (default: 10000). */
  maxSatsPerHour?: number;
  /** Maximum sats in a sliding 24-hour window (default: 50000). */
  maxSatsPerDay?: number;
  /** If set, only pay invoices from these domains. */
  allowedDomains?: Set<string>;
}

/** Credential cache configuration. */
export interface CacheOptions {
  /** Maximum cached credentials (default: 256). */
  maxSize?: number;
  /** Default TTL in milliseconds (default: 3600000 = 1 hour). */
  defaultTtlMs?: number;
}

/** A cached L402 credential (macaroon + preimage). */
export interface L402Credential {
  macaroon: string;
  preimage: string;
  createdAt: number;
  expiresAt: number | null;
}

/** A single L402 payment event. */
export interface PaymentRecord {
  domain: string;
  path: string;
  amountSats: number;
  preimage: string;
  timestamp: number;
  success: boolean;
}

/** Parsed L402 challenge from a WWW-Authenticate header. */
export interface L402Challenge {
  macaroon: string;
  invoice: string;
}

/** Options for the L402Client. */
export interface L402Options {
  /** Wallet adapter for paying invoices. If undefined, auto-detects. */
  wallet?: Wallet;
  /**
   * Budget controller. Pass `null` to disable budget limits.
   * Defaults to a BudgetController with sensible limits.
   */
  budget?: import("./budget.js").BudgetController | null;
  /** Credential cache. Defaults to a new CredentialCache. */
  credentialCache?: import("./credential-cache.js").CredentialCache;
  /** Additional options passed to fetch(). */
  fetchOptions?: RequestInit;
}

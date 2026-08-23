/** Lightning wallet adapter interface. */
export interface Wallet {
  /**
   * Whether this adapter returns the BOLT11 payment preimage from `payInvoice`.
   *
   * - `true` (or unset) — backend reliably surfaces the 32-byte preimage on
   *   settled outgoing payments (Strike, LND, NWC, and custom adapters from
   *   before this property existed). `L402Client` will use the wallet.
   * - `false` — backend does not surface the preimage (OpenNode). `L402Client`
   *   refuses to pay with this wallet, since L402 cannot complete without a
   *   preimage and an attempt would just burn the invoice.
   *
   * Optional for backwards compatibility: pre-existing custom `Wallet`
   * implementations that don't set this field are treated as `true` (assumed
   * preimage-capable). Only an EXPLICIT `false` triggers the fail-fast path.
   */
  readonly supportsPreimage?: boolean;

  /**
   * Pay a BOLT11 invoice and return the preimage (hex string).
   *
   * When `supportsPreimage` is `false`, the adapter still implements this
   * method but `L402Client` will not call it. If you call this directly (not
   * through `L402Client`), be prepared to catch `PaymentFailedError` from
   * adapters that pay successfully but can't surface the preimage (OpenNode).
   */
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

/** A cached credential obtained via L402 (macaroon + preimage). */
export interface L402CredentialL402 {
  scheme: "l402";
  macaroon: string;
  preimage: string;
  createdAt: number;
  expiresAt: number | null;
}

/** A cached credential obtained via MPP Payment scheme (preimage only). */
export interface L402CredentialMpp {
  scheme: "payment";
  macaroon: null;
  preimage: string;
  createdAt: number;
  expiresAt: number | null;
}

/** A cached payment credential — discriminated union of L402 and MPP. */
export type PaymentCredential = L402CredentialL402 | L402CredentialMpp;

/**
 * Alias for L402-based payment credentials (includes `scheme: "l402"`).
 *
 * NOTE: This type requires a `scheme: "l402"` discriminant field.
 * Code that previously constructed `{ macaroon, preimage, createdAt, expiresAt }`
 * without a `scheme` field must add `scheme: "l402"` to remain compatible.
 */
export type L402Credential = L402CredentialL402;

/** A single L402 payment event. */
export interface PaymentRecord {
  domain: string;
  path: string;
  amountSats: number;
  preimage: string;
  timestamp: number;
  success: boolean;
  /**
   * Macaroon from the parsed 402 challenge, recorded at payment time.
   * Together with `preimage` it forms the reusable L402 credential
   * (`Authorization: L402 {macaroon}:{preimage}`) needed by two-step
   * pay-then-claim flows. Empty string for MPP challenges (no macaroon).
   * Optional for backward compatibility with records created before v0.4.
   */
  macaroon?: string;
}

/** Parsed L402 challenge from a WWW-Authenticate header. */
export interface L402Challenge {
  macaroon: string;
  invoice: string;
}

/** MPP challenge parsed from a Payment WWW-Authenticate header.
 * Per IETF draft-ryan-httpauth-payment. */
export interface MppChallenge {
  invoice: string;
  amount?: string;
  realm?: string;
}

/**
 * Modern MPP challenge per draft-httpauth-payment-00 +
 * draft-lightning-charge-00, distinguished from the legacy profile by the
 * presence of the `request` param.
 *
 * The spec-defined challenge params (`id`, `realm`, `method`, `intent`,
 * `request`, `expires`, `digest`, `description`, `opaque`) are kept exactly
 * as received so the credential can echo them byte-for-byte —
 * `request` in particular is never decoded and re-encoded.
 */
export interface MppDraft00Challenge {
  /** BOLT11 invoice from the decoded `request` payload. */
  invoice: string;
  /** Amount in satoshis (decimal string) from the decoded `request`. */
  amount?: string;
  /** Currency from the decoded `request` (draft-00: "sat"). */
  currency?: string;
  /** Payment hash from the decoded `request`, when present. */
  paymentHash?: string;
  /** Lightning network from the decoded `request`, when present. */
  network?: string;
  /** Challenge id param, as received. */
  id?: string;
  /** Realm param, as received. */
  realm?: string;
  /** Method param, as received (draft-00: "lightning"). */
  method: string;
  /** Intent param, as received (draft-00: "charge"). */
  intent: string;
  /** The encoded `request` param EXACTLY as received. */
  request: string;
  /** Expires param (RFC3339), as received. */
  expires?: string;
  /** Digest param, as received. */
  digest?: string;
  /** Description param, as received. */
  description?: string;
  /** Opaque param, as received. */
  opaque?: string;
}

/**
 * Payment receipt decoded from a `Payment-Receipt` response header
 * (MPP draft-00). All fields optional — the header is parsed tolerantly.
 * The receipt carries only the payment hash (`reference`), never the
 * preimage, so it is safe to store.
 */
export interface PaymentReceipt {
  challengeId?: string;
  method?: string;
  /** Payment reference — the payment hash for lightning charges. */
  reference?: string;
  status?: string;
  timestamp?: string;
}

/**
 * Response returned by `L402Client` — a standard fetch Response, plus the
 * parsed `Payment-Receipt` header when the server sent one after payment.
 */
export type L402Response = Response & { paymentReceipt?: PaymentReceipt };

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

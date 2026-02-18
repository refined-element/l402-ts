/**
 * LRU credential cache for L402 tokens, keyed by "domain::path_prefix".
 *
 * Uses JS Map which preserves insertion order. Delete-then-set for move-to-end.
 * No locks needed (single-threaded).
 */

import type { L402Credential, CacheOptions } from "./types.js";

/**
 * Normalize domain and path into a cache key string.
 * Groups paths by their first two segments so /api/v1/foo and /api/v1/bar
 * share the same credential.
 */
function cacheKey(domain: string, path: string): string {
  domain = domain.toLowerCase().trim();
  const parts = path.split("/").filter(Boolean);
  const prefix =
    parts.length >= 2
      ? "/" + parts.slice(0, 2).join("/")
      : "/" + parts.join("/");
  return `${domain}::${prefix}`;
}

export class CredentialCache {
  private _maxSize: number;
  private _defaultTtlMs: number | null;
  private _cache = new Map<string, L402Credential>();

  constructor(options: CacheOptions = {}) {
    this._maxSize = options.maxSize ?? 256;
    this._defaultTtlMs = options.defaultTtlMs ?? 3_600_000; // 1 hour
  }

  /** Retrieve a cached credential for the given domain and path. */
  get(domain: string, path: string): L402Credential | null {
    const key = cacheKey(domain, path);
    const cred = this._cache.get(key);
    if (!cred) return null;

    // Check expiry
    if (cred.expiresAt !== null && Date.now() >= cred.expiresAt) {
      this._cache.delete(key);
      return null;
    }

    // Move to end (most recently used)
    this._cache.delete(key);
    this._cache.set(key, cred);
    return cred;
  }

  /** Store a credential in the cache. */
  put(
    domain: string,
    path: string,
    macaroon: string,
    preimage: string,
    expiresAt?: number | null,
  ): L402Credential {
    const key = cacheKey(domain, path);

    const resolvedExpiresAt =
      expiresAt !== undefined
        ? expiresAt
        : this._defaultTtlMs !== null
          ? Date.now() + this._defaultTtlMs
          : null;

    const cred: L402Credential = {
      macaroon,
      preimage,
      createdAt: Date.now(),
      expiresAt: resolvedExpiresAt ?? null,
    };

    // Delete first if exists (for move-to-end)
    this._cache.delete(key);
    this._cache.set(key, cred);

    // Evict oldest if over capacity
    while (this._cache.size > this._maxSize) {
      const oldest = this._cache.keys().next().value!;
      this._cache.delete(oldest);
    }

    return cred;
  }

  /** Build the Authorization header value for a credential. */
  static authorizationHeader(cred: L402Credential): string {
    return `L402 ${cred.macaroon}:${cred.preimage}`;
  }

  /** Remove all cached credentials. */
  clear(): void {
    this._cache.clear();
  }

  /** Number of cached credentials. */
  get size(): number {
    return this._cache.size;
  }
}

/**
 * Versioned User-Agent for every HTTP request the library issues.
 *
 * Servers (Lightning Enable's analytics among them) classify paid L402
 * traffic by the `l402-ts/` prefix, which keeps this package distinguishable
 * from the Python package that shares the `l402-requests` registry name.
 */

/**
 * Replaced with the package.json version at build time by tsup's `define`
 * (and by vitest's `define` under test). Never read from package.json at
 * runtime, so browser bundles carry no file access.
 */
declare const __PKG_VERSION__: string | undefined;

/** The injected version, or `0.0.0-dev` when none was injected (unbuilt source). */
export function resolvePackageVersion(injected: unknown): string {
  return typeof injected === "string" ? injected : "0.0.0-dev";
}

/** The package version, or `0.0.0-dev` when running unbuilt source. */
export const PACKAGE_VERSION: string = resolvePackageVersion(
  typeof __PKG_VERSION__ === "undefined" ? undefined : __PKG_VERSION__,
);

/** The User-Agent value this library sends: `l402-ts/<version>`. */
export const USER_AGENT = `l402-ts/${PACKAGE_VERSION}`;

interface EnvLike {
  window?: unknown;
  document?: unknown;
}

/**
 * True when the runtime looks like a browser (both `window` and `document`
 * globals exist), where `fetch` forbids setting `User-Agent`. Workers and
 * edge runtimes have neither, so they keep the header. Defaults to inspecting
 * `globalThis`; pass an object to test.
 */
export function isBrowserLike(env: EnvLike = globalThis as EnvLike): boolean {
  return (
    typeof env.window !== "undefined" && typeof env.document !== "undefined"
  );
}

/**
 * Set `User-Agent` on `headers` unless the caller already supplied one or the
 * runtime is browser-like. Mutates and returns `headers`.
 */
export function applyUserAgent(headers: Headers): Headers {
  if (!headers.has("User-Agent") && !isBrowserLike()) {
    headers.set("User-Agent", USER_AGENT);
  }
  return headers;
}

/**
 * The User-Agent as a plain header record for spreading into wallet requests;
 * empty in a browser-like runtime.
 */
export function userAgentHeaders(): Record<string, string> {
  return isBrowserLike() ? {} : { "User-Agent": USER_AGENT };
}

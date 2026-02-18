/** Base exception for l402-requests. */
export class L402Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = "L402Error";
  }
}

/** Payment would exceed configured budget limits. */
export class BudgetExceededError extends L402Error {
  constructor(
    public readonly limitType: string,
    public readonly limitSats: number,
    public readonly currentSats: number,
    public readonly invoiceSats: number,
  ) {
    super(
      `Budget exceeded: ${limitType} limit is ${limitSats} sats, ` +
        `already spent ${currentSats} sats, invoice requires ${invoiceSats} sats`,
    );
    this.name = "BudgetExceededError";
  }
}

/** Lightning payment failed. */
export class PaymentFailedError extends L402Error {
  constructor(
    public readonly reason: string,
    public readonly bolt11?: string,
  ) {
    super(`Payment failed: ${reason}`);
    this.name = "PaymentFailedError";
  }
}

/** Lightning invoice has expired. */
export class InvoiceExpiredError extends L402Error {
  constructor(public readonly bolt11?: string) {
    super("Invoice has expired");
    this.name = "InvoiceExpiredError";
  }
}

/** Failed to parse L402 challenge from WWW-Authenticate header. */
export class ChallengeParseError extends L402Error {
  constructor(
    public readonly header: string,
    public readonly reason: string,
  ) {
    super(`Failed to parse L402 challenge: ${reason}`);
    this.name = "ChallengeParseError";
  }
}

/** No wallet configured or auto-detected. */
export class NoWalletError extends L402Error {
  constructor() {
    super(
      "No wallet configured. Set environment variables for one of: " +
        "STRIKE_API_KEY, OPENNODE_API_KEY, NWC_CONNECTION_STRING, " +
        "LND_REST_HOST + LND_MACAROON_HEX",
    );
    this.name = "NoWalletError";
  }
}

/** Domain is not in the allowed domains list. */
export class DomainNotAllowedError extends L402Error {
  constructor(public readonly domain: string) {
    super(`Domain not in allowed list: ${domain}`);
    this.name = "DomainNotAllowedError";
  }
}

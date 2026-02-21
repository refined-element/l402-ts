# l402-requests

**Three lines of TypeScript. Paid APIs just work.**

```typescript
import { get } from 'l402-requests';

const response = await get("https://api.example.com/paid-resource");
console.log(await response.json());
```

That's the entire integration. No payment logic. No invoice parsing. No retry code. No protocol knowledge required.

Behind the scenes, `l402-requests` detects the 402 challenge, pays the Lightning invoice from your wallet, caches the credential, and retries the request. You get back a normal `Response`. The API just worked — and it got paid.

## Install

```bash
npm install l402-requests
```

Set one environment variable for your wallet and you're done:

```bash
export STRIKE_API_KEY="your-strike-api-key"
```

That's it. Every L402-protected API you call will automatically get paid.

## How It Works

```
  Your Code           l402-requests             L402 Server            Lightning
  ─────────           ─────────────             ───────────            ─────────
     │                     │                         │                     │
     │── GET /resource ──▶│                         │                     │
     │                     │── GET /resource ───────▶│                     │
     │                     │◀── 402 + invoice + mac ─│                     │
     │                     │                         │                     │
     │                     │  check budget           │                     │
     │                     │  extract amount          │                     │
     │                     │                         │                     │
     │                     │── pay invoice ──────────────────────────────▶│
     │                     │◀── preimage ────────────────────────────────│
     │                     │                         │                     │
     │                     │── GET /resource ────────▶│                     │
     │                     │   Authorization: L402    │                     │
     │                     │◀──── 200 + data ────────│                     │
     │◀── 200 + data ─────│                         │                     │
```

1. You make an HTTP request — `get(url)`
2. If the server returns **200**, the response comes back as-is
3. If the server returns **402** with an L402 challenge:
   - The invoice is parsed automatically
   - The amount is checked against your budget
   - The invoice is paid via your Lightning wallet
   - The request is retried with `Authorization: L402 {macaroon}:{preimage}`
4. Credentials are cached — subsequent requests to the same endpoint don't re-pay

## Wallet Configuration

Set environment variables for your wallet. The library auto-detects in priority order:

| Priority | Wallet | Environment Variables | Preimage | Notes |
|----------|--------|-----------------------|----------|-------|
| 1 | LND | `LND_REST_HOST` + `LND_MACAROON_HEX` | Yes | Requires running a node |
| 2 | NWC | `NWC_CONNECTION_STRING` | Yes | CoinOS, CLINK compatible |
| 3 | Strike | `STRIKE_API_KEY` | Yes | No infrastructure required |
| 4 | OpenNode | `OPENNODE_API_KEY` | Limited | No preimage support |

> **Recommended: Strike** — Full preimage support and requires no infrastructure. Set `STRIKE_API_KEY` and you're done.

### NWC (Nostr Wallet Connect)

NWC requires optional peer dependencies:

```bash
npm install @noble/secp256k1 ws
export NWC_CONNECTION_STRING="nostr+walletconnect://pubkey?relay=wss://relay&secret=hex"
```

### Explicit Wallet

```typescript
import { L402Client, StrikeWallet } from 'l402-requests';

const client = new L402Client({
  wallet: new StrikeWallet("your-key"),
});
const response = await client.get("https://api.example.com/paid-resource");
```

## Budget Controls

Safety is built in. Budgets are enabled by default so you can't accidentally overspend:

```typescript
import { L402Client, BudgetController } from 'l402-requests';

const client = new L402Client({
  budget: new BudgetController({
    maxSatsPerRequest: 500,     // Max per single payment (default: 1,000)
    maxSatsPerHour: 5000,       // Hourly rolling limit (default: 10,000)
    maxSatsPerDay: 25000,       // Daily rolling limit (default: 50,000)
    allowedDomains: new Set(["api.example.com"]),
  }),
});
```

If a payment would exceed any limit, `BudgetExceededError` is thrown **before** the payment is attempted — no sats leave your wallet.

To disable budgets entirely:

```typescript
const client = new L402Client({ budget: null }); // Not recommended
```

### Default Limits

| Limit | Default | Description |
|-------|---------|-------------|
| `maxSatsPerRequest` | 1,000 sats | Rejects any single invoice above this |
| `maxSatsPerHour` | 10,000 sats | Rolling 1-hour window |
| `maxSatsPerDay` | 50,000 sats | Rolling 24-hour window |

## Spending Introspection

Track every payment made during a session:

```typescript
const client = new L402Client();
await client.get("https://api.example.com/data");
await client.get("https://api.example.com/more-data");

console.log(`Total: ${client.spendingLog.totalSpent()} sats`);
console.log(`Last hour: ${client.spendingLog.spentLastHour()} sats`);
console.log(`Today: ${client.spendingLog.spentToday()} sats`);
console.log(`By domain:`, client.spendingLog.byDomain());
console.log(client.spendingLog.toJSON());
```

## Error Handling

```typescript
import { L402Client, BudgetExceededError, PaymentFailedError, NoWalletError } from 'l402-requests';

const client = new L402Client();

try {
  const response = await client.get("https://api.example.com/paid-resource");
} catch (e) {
  if (e instanceof BudgetExceededError) {
    console.log(`Over budget: ${e.limitType} limit is ${e.limitSats} sats`);
  } else if (e instanceof PaymentFailedError) {
    console.log(`Payment failed: ${e.reason}`);
  } else if (e instanceof NoWalletError) {
    console.log("No wallet configured");
  }
}
```

| Exception | When |
|-----------|------|
| `BudgetExceededError` | Payment would exceed a budget limit |
| `PaymentFailedError` | Lightning payment failed (routing, timeout, etc.) |
| `InvoiceExpiredError` | Invoice expired before payment |
| `NoWalletError` | No wallet env vars detected |
| `DomainNotAllowedError` | Domain not in `allowedDomains` |
| `ChallengeParseError` | Malformed L402 challenge header |

## Also Available

- **Python**: [`l402-requests`](https://pypi.org/project/l402-requests) — same "three lines of code" experience for Python
- **.NET**: [`L402Requests`](https://www.nuget.org/packages/L402Requests) — same experience for .NET

## Example: MaximumSats API

[MaximumSats](https://maximumsats.com) provides paid Lightning Network APIs including AI DVM, WoT reports, Nostr analysis, and more. Use l402-requests to automatically pay for these endpoints:

```typescript
import { get } from 'l402-requests';

const response = await get("https://maximumsats.com/api/dvm");
const data = await response.json();
```

Set your wallet via environment variable:

```bash
export STRIKE_API_KEY="your-strike-api-key"
```

The library automatically handles the L402 payment protocol — you just get the data.

## Source Code

[GitHub Repository](https://github.com/refined-element/l402-ts) (MIT License)

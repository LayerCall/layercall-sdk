# layercall

Official Node client for [LayerCall](https://www.layercall.com) — score an IP,
email, phone number, domain, or a whole signup for fraud in a single call.

**Zero dependencies.** A trust check sits on your signup path, which is the
worst place in an app to add a transitive dependency tree.

```bash
npm i layercall
```

## Quick start

```ts
import { LayerCall } from "layercall";

const lc = new LayerCall(process.env.LAYERCALL_API_KEY!);

const result = await lc.scoreUser({
  ip: req.ip,
  email: body.email,
  phone: body.phone,
});

if (result.verdict === "review") {
  await sendOtp(body.email);   // let a real user clear it themselves
} else if (result.verdict === "block") {
  await queueForReview(result);
}
```

[Get a free API key](https://www.layercall.com/get-key) — 1,000 lookups a
month, no card.

## Acting on a verdict

| Verdict | Do this | Not this |
| --- | --- | --- |
| `allow` | Let them through | — |
| `review` | **Step up** — OTP, SMS, 3-D Secure | Don't reject. This band includes ordinary VPN users. |
| `block` | Reject, or send to a human queue | Don't reject silently |

Prefer a challenge over a rejection. A real user clears it in seconds; an
attacker cannot. A false positive then costs friction instead of a customer.

**Already send an OTP to everyone?** Passwordless products can't use an email
code as a step-up — it's already mandatory. Score after sign-in and use a
different lever: a limited account state, a delayed payout or first send, or a
review queue.

## Methods

```ts
await lc.scoreIp("185.220.101.1");
await lc.verifyEmail("someone@mailinator.com");
await lc.lookupPhone("+14155552671");
await lc.lookupPhone("4155552671", { country: "US" });
await lc.scoreDomain("example.com");
await lc.scoreUser({ ip, email, phone, device_id });
await lc.batch("email", ["a@x.com", "b@y.com"]);   // up to 500
```

Every method takes `strictness` (`0` lenient → `3` paranoid). It moves the
verdict thresholds only; the risk score itself never changes, so you can
re-tune without re-scoring anything.

## Nulls mean unknown, never "no"

```ts
const { signals } = await lc.scoreDomain("example.de");
signals.newly_registered; // null — .de publishes no RDAP, so the age is unknown
```

`null` means we could not determine it. It is **not** a negative finding.
Treating it as "established" is exactly the mistake the field is designed to
prevent.

Same for `mailbox_exists`: Gmail and Yahoo accept mail for addresses that do
not exist, so we return `null` rather than a guess.

## Errors

```ts
import { LayerCallError } from "layercall";

try {
  await lc.scoreIp(ip);
} catch (err) {
  if (err instanceof LayerCallError) {
    if (err.isQuota) { /* 402 — out of quota or spend cap reached */ }
    if (err.isAuth)  { /* 401/403 — bad or revoked key */ }
    console.error(err.requestId); // quote this in a support ticket
  }
  // Fail open: let the signup through. Losing a real customer to our
  // downtime is worse than admitting one fraudster.
}
```

429s and 5xx are retried automatically (2 attempts, short exponential
backoff). Other 4xx fail fast — they will not succeed on a retry.

## Server-side only

The constructor throws if it detects a browser. An API key shipped to a
browser is public the moment someone opens devtools, and it bills to your
account.

## Options

```ts
new LayerCall({
  apiKey: process.env.LAYERCALL_API_KEY!,
  timeoutMs: 5000,   // per attempt
  retries: 2,        // 429 and 5xx only
});
```

## License

MIT

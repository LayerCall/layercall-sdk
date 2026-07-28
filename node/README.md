# layercall

> **Not yet on npm / PyPI.** Publishing is waiting on our payment provider
> approving the store — days, not weeks. The source here is complete and
> current; clone it if you want to try the client before then.

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

## Express

```bash
npm install layercall
```

```js
import { layercall } from "layercall/express";

app.post("/signup", layercall(), async (req, res) => {
  if (req.trust.verdict === "block") {
    return res.status(403).json({ error: "Could not verify this signup." });
  }
  if (req.trust.verdict === "review") {
    await flagForReview(req.body.email, req.trust.top_signals);
  }
  await createAccount(req.body);
});
```

Reads `LAYERCALL_API_KEY` from the environment, pulls `email` / `phone` /
`domain` / `device_id` out of `req.body`, and attaches the verdict as
`req.trust`.

**Mount it per route, not with `app.use()`.** Mounted globally it bills a
lookup for every POST your app receives, including ones that have nothing to do
with signing up.

**Set `trust proxy` if you run behind a CDN or load balancer.** Without it
Express reports the proxy's address, so every visitor looks like the same IP —
and that one IP accumulates every signal from every user, which is worse than
sending no IP at all.

```js
app.set("trust proxy", true);
```

### It never blocks for you

There is no `autoBlock` option. `req.trust` carries the verdict; the line that
rejects somebody is one you write. A one-line install that silently starts
refusing real customers is the wrong default for a fraud tool — you would find
out from a support ticket.

If you want the middleware to answer directly, pass `onBlock` and return `true`
once you have sent a response:

```js
layercall({
  onBlock: (req, res) => {
    res.status(403).json({ error: "Could not verify this signup." });
    return true; // handled — the route is not reached
  },
});
```

### It fails open

If LayerCall is unreachable, slow, or the account is over quota, the request
continues with `verdict: "allow"` and `scored: false`. A fraud check that takes
signups offline during an outage costs more than the fraud it was bought to
stop, and it hits every legitimate user at once rather than a few bad ones.

Branch on `scored` before doing anything punitive, and log it — a fallback
always reads `allow`, so code that only inspects `verdict` will let everything
through during an outage without ever saying so.

```js
if (!req.trust.scored) log.warn("layercall unavailable", req.trust.error);
```

### Options

| Option | Default | |
|---|---|---|
| `apiKey` | `process.env.LAYERCALL_API_KEY` | |
| `timeoutMs` | `2000` | sits in the request's critical path |
| `strictness` | API default | `0`–`3`; shifts the verdict, not the score |
| `shouldScore` | POST/PUT/PATCH | return `false` to skip a request |
| `extract` | reads `req.body` | pull the fields from somewhere else |
| `onBlock` | — | respond yourself; return `true` if handled |
| `property` | `"trust"` | rename `req.trust` |

## Next.js (App Router)

```js
import { scoreRequest } from "layercall/next";

export async function POST(req) {
  const trust = await scoreRequest(req);
  if (trust.verdict === "block") {
    return Response.json({ error: "Could not verify" }, { status: 403 });
  }
  const { email } = await req.json(); // body is still readable
  return Response.json(await createAccount(email));
}
```

Or wrap the handler:

```js
import { withTrust } from "layercall/next";

export const POST = withTrust(async (req, trust) => {
  if (trust.verdict === "block") return new Response(null, { status: 403 });
  return Response.json(await createAccount(await req.json()));
});
```

Same guarantees as Express: it fails open, and it never rejects on your behalf.

**Use it in route handlers, not `middleware.ts`.** Next.js middleware runs on
every matched request before routing, so scoring there adds LayerCall's latency
to page loads that have nothing to do with signups — and bills a lookup for
each one. Score where the account is actually created.

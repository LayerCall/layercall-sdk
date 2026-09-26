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

CommonJS works too, from 1.2.11:

```js
const { LayerCall } = require("layercall");
```

Up to 1.2.9 the package was ESM only, and `require` fails with
`ERR_PACKAGE_PATH_NOT_EXPORTED`. Upgrade, or use `await import("layercall")`.

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
// scoreDevice is the one method you cannot try without a browser: it needs a
// real fingerprint and the API correctly refuses anything else. On a TEST key
// these two fixtures work verbatim, so the line below is copy-pasteable today
// and you can wire up /fp.js afterwards.
await lc.scoreDevice({ device_id: "0".repeat(32) });               // clean browser
await lc.scoreDevice({ device_id: "f".repeat(32) });               // headless automation
await lc.scoreDevice({ device_id, ip, signals });   // real: fingerprint from /fp.js
await lc.scoreUser({ ip, email, phone, device_id });
await lc.batch("email", ["a@x.com", "b@y.com"]);   // up to 500

// AI agents — proof of identity, then your policy applied to it
await lc.verifyAgent({ url, headers });            // who is this?
await lc.authorizeAgent({ method, url, headers }); // may they do this, here?
await lc.getAgentPolicy();
await lc.setAgentPolicy([{ trigger: "crawler", path: "/api", action: "deny" }]);

// Tell us whether a score was right. Free, and the only thing that improves it.
await lc.reportOutcome({ request_id: r.request_id, outcome: "fraud" });

// Report confirmed fraud to the shared reputation network. Live keys only.
await lc.report("ip", "185.220.101.1", "carding");
```

### Custom rules — your lists always win

A rule overrides the computed score for that value. The kind (`ip`, `cidr`,
`email`, `domain`, `phone`, `asn`) is detected from the value unless you force
it.

```ts
await lc.addRules("block", ["185.220.101.1", "mailinator.com"]);
await lc.addRules("allow", "10.0.0.0/8");
await lc.addRules("block", ["AS14061"], { kind: "asn" });

const { count, rules } = await lc.listRules();
await lc.deleteRule(rules[0].id);

// Paste a list — one value per line, or CSV.
await lc.importRules("block", "1.2.3.4\n5.6.7.8\nspam.example");

// Removes EVERY rule on the account. `confirm` is required, deliberately.
await lc.clearRules({ confirm: true });
```

### A pending mailbox

`verifyEmail` returns `mailbox_status: "pending"` when the SMTP probe has not
finished — it is queued and the answer is there on the next lookup. If you
would rather wait for it, say so. It costs 2–10 seconds on a cache miss, which
is why it is opt-in:

```ts
const r = await lc.verifyEmail("someone@example.com", { waitForMailbox: true });
```

### AI agents

An AI agent does not evade fraud detection — it passes it. Real browser, real
fingerprint, residential address, a real mailbox that receives the code. Every
classical signal is a proxy for "is a human here", and an agent genuinely has
what those proxies measure.

So `scoreUser` returns an `actor` block that says what kind of thing this is,
and the field to branch on is `proven`:

```ts
const r = await lc.scoreUser({ ip, email, device_id, agent: { method, url, headers } });

r.actor.type    // "verified_agent" | "impersonated_agent" | "automation"
                // | "likely_human" | "unknown"
r.actor.proven  // true ONLY for a verified cryptographic signature
r.agent?.decision  // "allow" | "deny" | "review" — your policy, if you passed `agent`
```

`proven` is true for exactly one thing: a Web Bot Auth signature that verified.
That is arithmetic and has no false-positive rate. Headless detection and
automation markers are inference, and inference a capable adversary patches in
an afternoon. Branch on `proven` and you will never mistake one for the other.

There is deliberately no `"human"` value. A capable agent driving a real browser
passes every human check, so `likely_human` means *nothing here looks
automated* — a statement about our evidence, not about your visitor.

### Patterns across values

`scoreUser` also returns `linkage`. Forty signups from forty clean addresses
with forty plausible inboxes each score allow, correctly — each one really is
unremarkable. What gives the operator away is one device seen with twelve
emails, or fifty lookups from one /24 in an hour.

```ts
r.linkage.device_email_count  // distinct emails on this device
r.linkage.subnet_rate_1h      // lookups from this /24 in the last hour
```

A `null` means we do not know. It never means zero.

Every **scoring** method takes `strictness` (`0` lenient → `3` paranoid) —
`scoreIp`, `verifyEmail`, `lookupPhone`, `scoreDomain`, `scoreDevice`,
`scoreUser` and `batch`. It moves the verdict thresholds only; the risk score
itself never changes, so you can re-tune without re-scoring anything.

The other methods report or configure rather than score, and take no
strictness: `report`, `reportOutcome`, `verifyAgent`, `authorizeAgent`,
`getAgentPolicy`, `setAgentPolicy`.

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

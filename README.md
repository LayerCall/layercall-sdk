# LayerCall SDKs

[![npm](https://img.shields.io/npm/v/layercall?label=npm&color=cb3837)](https://www.npmjs.com/package/layercall)
[![PyPI](https://img.shields.io/pypi/v/layercall?label=PyPI&color=3775a9)](https://pypi.org/project/layercall/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](#)

Official clients for [LayerCall](https://www.layercall.com) — score an IP,
email, phone number, domain, or a whole signup for fraud in a single call.

| | Install | Docs |
| --- | --- | --- |
| **Node / TypeScript** | `npm i layercall` | [node/README.md](node/README.md) |
| **Python** | `pip install layercall` | [python/README.md](python/README.md) |
| **CLI** | `npx layercall ip 8.8.8.8` | below |

Both clients have **zero dependencies**. A trust check sits on your signup
path, which is the worst place in an application to introduce a dependency
tree.

[Get a free API key](https://www.layercall.com/get-key) — 1,000 lookups a
month, no card required, no daily cap.

## Try it without installing anything

```bash
export LAYERCALL_API_KEY=tl_live_...
npx layercall ip 8.8.8.8
npx layercall email someone@mailinator.com
npx layercall domain example.com
npx layercall user --ip 1.2.3.4 --email a@b.com
```

## What it returns

Every endpoint returns the same shape: a `0–100` `risk_score`, an
`allow | review | block` verdict, and the signals behind it.

```json
{
  "ip": "185.220.101.1",
  "risk_score": 60,
  "verdict": "review",
  "signals": {
    "is_vpn": true,
    "is_proxy": true,
    "is_datacenter": true,
    "is_tor": true,
    "recent_abuse": false
  },
  "geo": { "country": "DE", "city": "Berlin", "asn": "AS60729" },
  "vpn_provider": null
}
```

## Two things worth reading before you integrate

**Prefer step-up over rejection.** The `review` band starts where an ordinary
commercial VPN lands, and most VPN users are ordinary customers. Send them an
OTP or a 3-D Secure challenge instead of a refusal: a real user clears it in
seconds, an attacker cannot, and a false positive costs friction rather than a
customer. This is what Stripe Radar and Sift both converged on.

**`null` means unknown, not "no".** `newly_registered` is `null` when a TLD
publishes no RDAP (`.de`, `.ru`, `.ac.uk` among them), and `mailbox_exists` is
`null` when the mail provider does not answer honestly — Gmail and Yahoo accept
mail for addresses that do not exist. Treating either as a negative finding is
the specific mistake these fields exist to prevent.

## Endpoints

| | |
| --- | --- |
| `POST/GET /v1/score/ip` | VPN, proxy, Tor, datacenter, geo, ASN |
| `/v1/verify/email` | Syntax, MX, disposable, role account, domain age |
| `/v1/lookup/phone` | Numbering-plan validation worldwide, line type |
| `/v1/score/domain` | RDAP age, registrar, MX/SPF/DMARC, risky TLD |
| `/v1/score/device` | Device fingerprint reputation + bot probability |
| `/v1/score/user` | All of the above weighted into one verdict |
| `/v1/verify/agent` | Web Bot Auth (RFC 9421) — prove an AI agent is who it claims |
| `/v1/batch` | Up to 500 values of one type |

Full reference: [layercall.com/docs](https://www.layercall.com/docs) ·
OpenAPI 3.1: [layercall.com/openapi.json](https://www.layercall.com/openapi.json)

## Testing without spending anything

Test-mode keys return deterministic **synthetic** data, drawn from ranges
reserved for exactly this purpose — RFC 5737 addresses, `example.com`, the
555-01XX fiction block. Same shape and fields as production, so your assertions
are real ones. They never bill, never hit live data sources, and never write to
the shared reputation network.

Every fixture is documented, so you can assert on exact values rather than
"did it return a number": [layercall.com/docs/test-mode](https://www.layercall.com/docs/test-mode)

## MCP — call it from an AI agent

LayerCall speaks the Model Context Protocol over Streamable HTTP, so Claude
Code, Claude Desktop, ChatGPT, Cursor, VS Code, Windsurf and Zed can run a
fraud check mid-conversation. There is nothing to install — it is a remote
server, so you add a URL and your API key:

```json
{
  "mcpServers": {
    "layercall": {
      "url": "https://www.layercall.com/api/mcp",
      "headers": { "Authorization": "Bearer YOUR_API_KEY" }
    }
  }
}
```

Seven tools are exposed: `score_ip`, `verify_email`, `lookup_phone`,
`score_domain`, `score_device`, `verify_agent` and `score_user`.

> VS Code names the top-level key `servers`, not `mcpServers`. That one
> difference is the usual reason a copied config silently does nothing.

Per-client setup: [layercall.com/docs/mcp](https://www.layercall.com/docs/mcp)

## Framework middleware

Drop-in for the two places this usually goes. The middleware attaches
`req.trust` and leaves the decision to you:

```ts
import { layercall } from "layercall/express";

app.post("/signup", layercall(), (req, res) => {
  if (req.trust.verdict === "block") return res.status(403).json({ error: "..." });
  if (req.trust.verdict === "review") flagForManualReview(req.trust);
  createAccount(req.body);
});
```

There is deliberately no `autoBlock: true`. A one-line install that starts
rejecting people is the wrong default for a fraud tool — the failure is silent,
it lands on real customers, and you find out from a support ticket.

By default it only scores `POST`/`PUT`/`PATCH`, because a global `app.use()`
bills a lookup for every request including `favicon.ico`.

See [node/src/express.ts](node/src/express.ts) and
[node/src/next.ts](node/src/next.ts) (`scoreRequest`, `withTrust`).

## Guides

Written for someone mid-incident rather than someone shopping. Each one ends
with what a naive version gets wrong — including the parts that need no
LayerCall at all.

- [How to stop fake signups](https://www.layercall.com/guides/stop-fake-signups)
- [How to block disposable email addresses at signup](https://www.layercall.com/guides/block-disposable-emails)
- [How to detect VPN and proxy users at signup](https://www.layercall.com/guides/detect-vpn-at-signup)
- [How to stop free trial abuse](https://www.layercall.com/guides/stop-free-trial-abuse)
- [How to add fraud checks without losing real customers](https://www.layercall.com/guides/score-signup-without-blocking-real-users)

## License

MIT

# LayerCall SDKs

> **Not yet on npm / PyPI.** Publishing is waiting on our payment provider
> approving the store — days, not weeks. The source here is complete and
> current; clone it if you want to try the client before then.

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
month, no card required.

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
| `/v1/batch` | Up to 500 values of one type |

Full reference: [layercall.com/docs](https://www.layercall.com/docs) ·
OpenAPI 3.1: [layercall.com/openapi.json](https://www.layercall.com/openapi.json)

## MCP

LayerCall also speaks the Model Context Protocol, so Claude, Cursor, ChatGPT,
VS Code, Windsurf and Zed can call it mid-conversation:

```
https://www.layercall.com/api/mcp
```

Setup: [layercall.com/docs/mcp](https://www.layercall.com/docs/mcp)

## License

MIT

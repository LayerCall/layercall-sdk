# layercall

Official Python client for [LayerCall](https://www.layercall.com) — score an
IP, email, phone number, domain, or a whole signup for fraud in a single call.

**Zero dependencies.** Standard library only. A trust check sits on your signup
path, which is the worst place to add a dependency tree that has to resolve
against whatever your app already pins.

```bash
pip install layercall
```

## Quick start

```python
import os
from layercall import LayerCall

lc = LayerCall(os.environ["LAYERCALL_API_KEY"])

result = lc.score_user(ip=request.remote_addr, email=form["email"])

if result["verdict"] == "review":
    send_otp(form["email"])      # a real user clears it themselves
elif result["verdict"] == "block":
    queue_for_review(result)
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
different lever: a limited account state, a delayed payout, or a review queue.

## Methods

```python
lc.score_ip("185.220.101.1")
lc.verify_email("someone@mailinator.com")
lc.lookup_phone("+14155552671")
lc.lookup_phone("4155552671", country="US")
lc.score_domain("example.com")
lc.score_device(device_id, ip=ip, signals=signals)   # fingerprint from /fp.js
lc.score_user(ip=ip, email=email, phone=phone, device_id=device_id)
lc.batch("email", ["a@x.com", "b@y.com"])            # up to 500

# AI agents — proof of identity, then your policy applied to it
lc.verify_agent(url=url, headers=headers)            # who is this?
lc.authorize_agent(method=method, url=url, headers=headers)  # may they, here?
lc.get_agent_policy()
lc.set_agent_policy([{"trigger": "crawler", "path": "/api", "action": "deny"}])

# Tell us whether a score was right. Free, and the only thing that improves it.
lc.report_outcome(request_id=r["request_id"], outcome="fraud")

# Report confirmed fraud to the shared reputation network. Live keys only.
lc.report("ip", "185.220.101.1", reason="carding")
```

### Custom rules - your lists always win

A rule overrides the computed score for that value. The kind (`ip`, `cidr`,
`email`, `domain`, `phone`, `asn`) is detected from the value unless you force
it.

```python
lc.add_rules("block", ["185.220.101.1", "mailinator.com"])
lc.add_rules("allow", "10.0.0.0/8")
lc.add_rules("block", ["AS14061"], kind="asn")

listed = lc.list_rules()
lc.delete_rule(listed["rules"][0]["id"])

# Paste a list - one value per line, or CSV.
lc.import_rules("block", "1.2.3.4\n5.6.7.8\nspam.example")

# Removes EVERY rule on the account. confirm is required, deliberately.
lc.clear_rules(confirm=True)
```

### A pending mailbox

`verify_email` returns `mailbox_status` `"pending"` when the SMTP probe has not
finished - it is queued and the answer is there on the next lookup. If you
would rather wait for it, say so. It costs 2-10 seconds on a cache miss, which
is why it is opt-in:

```python
r = lc.verify_email("someone@example.com", wait_for_mailbox=True)
```

That is all thirteen. This block used to list seven, with no hint there were
more — so a Python developer reasonably concluded that device scoring, agent
authorization and outcome feedback were Node-only features. They were not;
they were shipped, working and undocumented.

Every **scoring** method takes `strictness` (`0` lenient → `3` paranoid) —
`score_ip`, `verify_email`, `lookup_phone`, `score_domain`, `score_device`,
`score_user` and `batch`. It moves the verdict thresholds only; the risk score
never changes, so you can re-tune without re-scoring anything.

The other methods report or configure rather than score, and take no
strictness: `report`, `report_outcome`, `verify_agent`, `authorize_agent`,
`get_agent_policy`, `set_agent_policy`.

## None means unknown, never "no"

```python
signals = lc.score_domain("example.de")["signals"]
signals["newly_registered"]   # None — .de publishes no RDAP, so age is unknown
```

`None` means we could not determine it. It is **not** a negative finding.
Treating it as "established" is exactly the mistake the field exists to
prevent.

Same for `mailbox_exists`: Gmail and Yahoo accept mail for addresses that do
not exist, so we return `None` rather than a guess.

## Errors

```python
from layercall import LayerCallError

try:
    lc.score_ip(ip)
except LayerCallError as err:
    if err.is_quota:   # 402 — out of quota or spend cap reached
        ...
    if err.is_auth:    # 401/403 — bad or revoked key
        ...
    print(err.request_id)   # quote this in a support ticket
except Exception:
    pass   # fail open: let the signup through
```

429s and 5xx retry automatically (2 attempts, short backoff). Other 4xx fail
fast — they will not succeed on a retry.

## Server-side only

An API key in anything a user can read is public and bills to your account.

## License

MIT

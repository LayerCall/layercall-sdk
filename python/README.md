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
lc.score_user(ip=ip, email=email, phone=phone, device_id=device_id)
lc.batch("email", ["a@x.com", "b@y.com"])       # up to 500
```

Every method takes `strictness` (`0` lenient → `3` paranoid). It moves the
verdict thresholds only; the risk score never changes, so you can re-tune
without re-scoring anything.

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

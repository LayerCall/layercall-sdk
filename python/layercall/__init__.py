"""Official LayerCall client.

Score an IP, email, phone number, domain, or a whole signup for fraud in a
single call.

Zero dependencies, standard library only. A trust check sits on the signup
path, which is the worst place in an application to introduce a dependency
tree that has to be resolved against whatever the host app already pins.

Test keys return synthetic data
-------------------------------
A key beginning ``tl_test_`` returns fabricated scores and signals, derived
from the value you sent rather than from anything known about it. Response
shapes, error codes and your own allow/block rules behave exactly as in
production, so integration tests against a test key are valid — the numbers
are not. Those responses carry ``test_mode: True`` and a ``test_mode_note``.

    result = client.score_ip("8.8.8.8")
    if result.get("test_mode"):
        ...  # pointed at a test key, do not assert on risk_score

Use a ``tl_live_`` key to score real values.
See https://www.layercall.com/docs/test-mode
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Literal, Mapping, Sequence

__version__ = "1.2.11"
# Verdict and Strictness are part of the signature — `verdict: Verdict` and
# `strictness: Strictness` appear on the public methods below — so a caller
# writing a type annotation needs them, and `from layercall import *` was not
# giving them out.
__all__ = ["LayerCall", "LayerCallError", "Verdict", "Strictness"]

Verdict = Literal["allow", "review", "block"]
Strictness = Literal[0, 1, 2, 3]

_DEFAULT_BASE = "https://www.layercall.com"


class LayerCallError(Exception):
    """A non-2xx response. Branch on ``status`` or ``code``."""

    def __init__(
        self,
        message: str,
        status: int,
        code: str | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.request_id = request_id

    @property
    def is_quota(self) -> bool:
        """Quota exhausted or spend cap reached — upgrade or raise the cap."""
        return self.status == 402

    @property
    def is_auth(self) -> bool:
        """Bad or revoked key."""
        return self.status in (401, 403)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"LayerCallError(status={self.status}, code={self.code!r}, message={self!s})"


class LayerCall:
    """Client for the LayerCall API.

    Server-side only. An API key in anything a user can read is public, and it
    bills to your account.

        lc = LayerCall(os.environ["LAYERCALL_API_KEY"])
        result = lc.score_user(ip=request.remote_addr, email=form["email"])
        if result["verdict"] == "review":
            send_otp(form["email"])       # a real user clears it themselves
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = _DEFAULT_BASE,
        timeout: float = 30.0,
        retries: int = 2,
    ) -> None:
        if not api_key:
            raise ValueError("LayerCall: api_key is required.")
        self._key = api_key
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        # /v1/batch alone budgets 300s server-side, so the normal default would
        # abandon a large batch mid-flight and bill every item in it.
        self._batch_timeout = max(timeout, 300.0)
        self._retries = retries

    # -- transport --------------------------------------------------------

    def _request(
        self,
        path: str,
        *,
        query: Mapping[str, Any] | None = None,
        body: Mapping[str, Any] | None = None,
        method: str | None = None,
    ) -> dict[str, Any]:
        """Send one request.

        `method` exists because six public methods already passed it and this
        signature did not accept it: score_device, verify_agent,
        authorize_agent, set_agent_policy, report_outcome and report every one
        raised TypeError before opening a socket. That is nearly half the
        surface of a package published to PyPI, including the copy-paste
        example in the agent docs.

        It survived because the SDK's own smoke test exercised the working
        seven, and the one method the docs headline with — score_user — is in
        that set. Inferring the verb from body-presence was also not enough on
        its own: set_agent_policy needs PUT, which no amount of body inspection
        can produce.
        """
        url = self._base + path
        if query:
            clean = {k: v for k, v in query.items() if v is not None}
            if clean:
                url += "?" + urllib.parse.urlencode(clean)

        data = json.dumps(body).encode() if body is not None else None
        last_exc: Exception | None = None

        for attempt in range(self._retries + 1):
            req = urllib.request.Request(
                url,
                data=data,
                method=method or ("POST" if data is not None else "GET"),
                headers={
                    "X-Api-Key": self._key,
                    "Content-Type": "application/json",
                    "User-Agent": f"layercall-python/{__version__}",
                },
            )
            try:
                timeout = (
                    self._batch_timeout if path == "/v1/batch" else self._timeout
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return json.loads(resp.read().decode() or "{}")
            except urllib.error.HTTPError as exc:
                try:
                    payload = json.loads(exc.read().decode() or "{}")
                except Exception:
                    payload = {}
                err = LayerCallError(
                    payload.get("error") or f"HTTP {exc.code}",
                    exc.code,
                    payload.get("code"),
                    payload.get("request_id"),
                )
                # A 4xx other than 429 fails identically on retry. Surfacing it
                # now beats spending a signup path's latency budget proving it.
                if not (exc.code == 429 or exc.code >= 500) or attempt == self._retries:
                    raise err from None
                last_exc = err
            except Exception as exc:  # timeouts, DNS, connection resets
                # A TIMEOUT IS NOT EVIDENCE THAT THE SERVER FAILED.
                #
                # It only says we stopped waiting. The request very likely
                # arrived and is still being processed - and it will finish,
                # meter a billable lookup, and return to nobody. Retrying does
                # not recover that lookup, it buys a second one. With the old
                # 5s default against a 25-second endpoint budget, one logical
                # call became three billable ones and the caller still got an
                # error.
                #
                # Refused, reset or DNS means the request never reached us, so
                # a retry is free and worth making. Those still retry.
                if isinstance(exc, TimeoutError) or isinstance(
                    getattr(exc, "reason", None), TimeoutError
                ):
                    raise
                last_exc = exc
                if attempt == self._retries:
                    break
            # Short exponential backoff — this sits in front of a user.
            time.sleep(0.15 * (2**attempt))

        raise last_exc if last_exc else RuntimeError("LayerCall: request failed")

    # -- endpoints --------------------------------------------------------

    def score_ip(self, ip: str, *, strictness: Strictness | None = None) -> dict[str, Any]:
        """VPN, proxy, Tor, datacenter, geolocation and ASN for an IP."""
        return self._request("/v1/score/ip", query={"ip": ip, "strictness": strictness})

    def verify_email(
        self,
        email: str,
        *,
        strictness: Strictness | None = None,
        wait_for_mailbox: bool = False,
    ) -> dict[str, Any]:
        """Syntax, MX, disposable, role account, homograph and domain age.

        wait_for_mailbox blocks until the SMTP mailbox probe finishes rather
        than returning mailbox_status "pending". It is the documented remedy
        for a pending mailbox, and it was reachable only by hand-writing the
        HTTP call - the docs told you to pass it and the recommended client had
        no way to. Costs 2-10 seconds on a cache miss, which is why it is
        opt-in.
        """
        return self._request(
            "/v1/verify/email",
            query={
                "email": email,
                "strictness": strictness,
                "wait_for_mailbox": "true" if wait_for_mailbox else None,
            },
        )

    def lookup_phone(
        self,
        phone: str,
        *,
        country: str | None = None,
        strictness: Strictness | None = None,
    ) -> dict[str, Any]:
        """Numbering-plan validation worldwide. ``country`` only for national format."""
        return self._request(
            "/v1/lookup/phone",
            query={"phone": phone, "country": country, "strictness": strictness},
        )

    def score_domain(self, domain: str, *, strictness: Strictness | None = None) -> dict[str, Any]:
        """RDAP registration date, registrar, MX/SPF/DMARC, risky TLD."""
        return self._request(
            "/v1/score/domain",
            query={"domain": domain, "strictness": strictness},
        )

    def score_device(
        self,
        device_id: str,
        *,
        ip: str | None = None,
        signals: dict[str, Any] | None = None,
        automation: dict[str, Any] | None = None,
        strictness: Strictness | None = None,
    ) -> dict[str, Any]:
        """Score a device fingerprint from /fp.js.

        POST, never GET: a device id in a URL lands in access logs and Referer
        headers, and that is a tracking identifier.

        ``strictness`` rides in the query string, not the body — the route
        reads it from the URL for every endpoint, POST ones included.
        """
        body: dict[str, Any] = {"device_id": device_id}
        if ip is not None:
            body["ip"] = ip
        if signals is not None:
            body["signals"] = signals
        if automation is not None:
            body["automation"] = automation
        return self._request(
            "/v1/score/device",
            method="POST",
            body=body,
            query={"strictness": strictness},
        )

    def verify_agent(
        self,
        url: str,
        headers: dict[str, str],
        *,
        method: str = "GET",
    ) -> dict[str, Any]:
        """Verify a Web Bot Auth signature — proof of WHICH agent is calling.

        Pass the request the agent made to YOU: the signature covers its
        method, authority and path, so none of it can be inferred from our
        side.

        The only check here that proves rather than infers, so there is no
        score and no verdict. What to do about a verified agent is your policy.
        """
        return self._request(
            "/v1/verify/agent",
            method="POST",
            body={"method": method, "url": url, "headers": headers},
        )

    def authorize_agent(
        self,
        url: str,
        headers: dict[str, str],
        *,
        method: str = "GET",
    ) -> dict[str, Any]:
        """Should this agent be allowed to do this, here?

        verify_agent() answers "who is this" and stops there. This applies your
        policy to that answer and returns a decision with the rule that made it.

        Use score_user(agent=...) instead when there is a signup identity to
        score alongside it — one call does both.
        """
        return self._request(
            "/v1/agent/authorize",
            method="POST",
            body={"method": method, "url": url, "headers": headers},
        )

    def get_agent_policy(self) -> dict[str, Any]:
        """Read your agent authorization policy. Free."""
        return self._request("/v1/agent/policy")

    def set_agent_policy(self, rules: list[dict[str, Any]]) -> dict[str, Any]:
        """Replace your agent authorization policy. Free.

        Rules are evaluated in order and the first match wins. An empty policy
        is not an open door: the defaults still deny an unverifiable signature
        and refuse a self-declared crawler attempting to change state.
        """
        return self._request("/v1/agent/policy", method="PUT", body={"rules": rules})

    def report_outcome(
        self,
        request_id: str | list[dict[str, Any]],
        outcome: str | None = None,
    ) -> dict[str, Any]:
        """Tell us whether a score was right. Free.

        Pass the request_id from the score you are reporting on, plus "fraud"
        or "legitimate". Or pass a list of {"request_id", "outcome"} dicts — a
        day of chargebacks is a list, not 500 separate requests.

        This is the only way either of us finds out whether the thresholds suit
        your traffic. A "fraud" label also raises the abuse counters on every
        value in that score across the whole network, so your confirmed loss
        protects the next customer immediately.
        """
        body: Any = (
            request_id
            if isinstance(request_id, list)
            else {"request_id": request_id, "outcome": outcome}
        )
        return self._request("/v1/outcome", method="POST", body=body)

    def report(
        self,
        kind: str,
        value: str,
        *,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Report a value as confirmed fraud, feeding the reputation network.

        Live keys only — a test key is refused, because test traffic must never
        teach the network something a suite invented.
        """
        body: dict[str, Any] = {"kind": kind, "value": value}
        if reason is not None:
            body["reason"] = reason
        return self._request("/v1/report", method="POST", body=body)

    def score_user(

        self,
        *,
        ip: str | None = None,
        email: str | None = None,
        phone: str | None = None,
        phone_country: str | None = None,
        domain: str | None = None,
        device_id: str | None = None,
        device_signals: dict[str, Any] | None = None,
        device_automation: dict[str, Any] | None = None,
        agent: dict[str, Any] | None = None,
        strictness: Strictness | None = None,
    ) -> dict[str, Any]:
        """Score a whole signup, in one call.

        Returns `summary` — one sentence describing the decision, for a Slack
        alert or a review ticket — plus risk_score and verdict, `actor` (what
        kind of thing this is, with `proven` true only for a verified
        signature) and `linkage` (patterns across values that no single value
        can show).

        Pass `agent={"method", "url", "headers"}` — the signed request an AI
        agent made to YOU — to get an authorization decision in the same call.
        A denied agent forces the verdict to block, because that is your own
        policy and reporting allow would overrule you.

        A block on any single component floors the combined score at review, so
        one definitive red flag is never averaged away by four clean ones. It
        stops at review rather than block on purpose: one certain component is
        not a certain signup. Raise strictness to 2 if you want that floor to
        land on block.
        """
        payload = {
            k: v
            for k, v in {
                "ip": ip,
                "email": email,
                "phone": phone,
                "phone_country": phone_country,
                "domain": domain,
                "device_id": device_id,
                # Declared on the signature and dropped from the payload is the
                # same bug the API route itself shipped with: no error, just a
                # component quietly missing from components_checked.
                "device_signals": device_signals,
                "device_automation": device_automation,
                "agent": agent,
                "strictness": strictness,
            }.items()
            if v is not None
        }
        if not payload:
            raise ValueError("score_user: provide at least one of ip, email or phone.")
        return self._request("/v1/score/user", body=payload)

    # -- custom rules -----------------------------------------------------
    #
    # One of the nine products on the homepage, three endpoints, and until now
    # no method in either SDK for any of them. A customer following our own
    # advice to use the SDK found a promoted feature reachable only by
    # hand-writing HTTP, and would reasonably conclude it was unfinished.
    #
    # A rule's kind (ip, cidr, email, domain, phone, asn) is detected from the
    # value unless you force it.

    def list_rules(self) -> dict[str, Any]:
        """Every rule on the account."""
        return self._request("/v1/rules")

    def add_rules(
        self,
        action: str,
        values: str | list[str],
        *,
        kind: str | None = None,
    ) -> dict[str, Any]:
        """Add one rule or many. Re-adding an existing rule is idempotent."""
        body: dict[str, Any] = {
            "action": action,
            "values": [values] if isinstance(values, str) else list(values),
        }
        if kind is not None:
            body["kind"] = kind
        return self._request("/v1/rules", body=body)

    def delete_rule(self, rule_id: str) -> dict[str, Any]:
        """Remove one rule by id."""
        return self._request(f"/v1/rules/{urllib.parse.quote(rule_id, safe='')}", method="DELETE")

    def clear_rules(self, *, confirm: bool = False) -> dict[str, Any]:
        """Remove EVERY rule on the account.

        confirm=True is required by the API and deliberately not defaulted
        here - the whole point of the flag is that it cannot happen by
        accident, and an SDK that fills it in for you removes the guard.
        """
        if not confirm:
            raise ValueError(
                "clear_rules deletes every rule on the account - pass confirm=True."
            )
        return self._request("/v1/rules", method="DELETE", query={"confirm": "true"})

    def import_rules(
        self,
        action: str,
        text: str,
        *,
        kind: str | None = None,
    ) -> dict[str, Any]:
        """Import rules from pasted text - one value per line, or CSV."""
        body: dict[str, Any] = {"action": action, "text": text}
        if kind is not None:
            body["kind"] = kind
        return self._request("/v1/rules/import", body=body)

    def batch(
        self,
        type: Literal["ip", "email", "phone", "domain"],
        items: Sequence[str],
        *,
        strictness: Strictness | None = None,
        phone_country: str | None = None,
    ) -> dict[str, Any]:
        """Up to 500 values of one type. Each item carries its own error."""
        if len(items) > 500:
            raise ValueError(
                f"batch: {len(items)} items exceeds the limit of 500 — send several batches."
            )
        payload: dict[str, Any] = {"type": type, "items": list(items)}
        if strictness is not None:
            payload["strictness"] = strictness
        if phone_country is not None:
            payload["phone_country"] = phone_country
        return self._request("/v1/batch", body=payload)

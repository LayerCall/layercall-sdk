"""Official LayerCall client.

Score an IP, email, phone number, domain, or a whole signup for fraud in a
single call.

Zero dependencies, standard library only. A trust check sits on the signup
path, which is the worst place in an application to introduce a dependency
tree that has to be resolved against whatever the host app already pins.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Literal, Mapping, Sequence

__version__ = "1.0.0"
__all__ = ["LayerCall", "LayerCallError"]

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
        timeout: float = 5.0,
        retries: int = 2,
    ) -> None:
        if not api_key:
            raise ValueError("LayerCall: api_key is required.")
        self._key = api_key
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._retries = retries

    # -- transport --------------------------------------------------------

    def _request(
        self,
        path: str,
        *,
        query: Mapping[str, Any] | None = None,
        body: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
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
                method="POST" if data is not None else "GET",
                headers={
                    "X-Api-Key": self._key,
                    "Content-Type": "application/json",
                    "User-Agent": f"layercall-python/{__version__}",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:
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

    def verify_email(self, email: str, *, strictness: Strictness | None = None) -> dict[str, Any]:
        """Syntax, MX, disposable, role account, homograph and domain age."""
        return self._request("/v1/verify/email", query={"email": email, "strictness": strictness})

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

    def score_domain(self, domain: str) -> dict[str, Any]:
        """RDAP registration date, registrar, MX/SPF/DMARC, risky TLD."""
        return self._request("/v1/score/domain", query={"domain": domain})

    def score_user(
        self,
        *,
        ip: str | None = None,
        email: str | None = None,
        phone: str | None = None,
        phone_country: str | None = None,
        domain: str | None = None,
        device_id: str | None = None,
        strictness: Strictness | None = None,
    ) -> dict[str, Any]:
        """Score a whole signup. A hard block on one component is never averaged away."""
        payload = {
            k: v
            for k, v in {
                "ip": ip,
                "email": email,
                "phone": phone,
                "phone_country": phone_country,
                "domain": domain,
                "device_id": device_id,
                "strictness": strictness,
            }.items()
            if v is not None
        }
        if not payload:
            raise ValueError("score_user: provide at least one of ip, email or phone.")
        return self._request("/v1/score/user", body=payload)

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

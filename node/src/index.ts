/**
 * Official LayerCall client.
 *
 * Zero dependencies and one file on purpose. A trust check sits on the signup
 * path, which is the worst place in an application to introduce a transitive
 * dependency tree, a supply-chain surface, or a version conflict with whatever
 * the host app already uses.
 */

export type Verdict = "allow" | "review" | "block";

/** 0 lenient · 1 balanced (default) · 2 strict · 3 paranoid. */
export type Strictness = 0 | 1 | 2 | 3;

// Response types, generated from LIVE responses rather than written by hand.
//
// The hand-written versions had drifted badly and nothing caught it, because a
// wrong type is not a runtime error — it is a compile-time lie. EmailResult
// omitted eleven fields the API returns, including normalized_email,
// deliverability_score, mx_provider and digital_footprint, so a TypeScript
// user could not reach most of the email product without a cast. Three types
// also declared request_id, which those endpoints do not return, promising a
// string that arrives undefined.
//
// test/api-contract.test.mjs now compares these against the live API in both
// directions on every CI run. Add a field to a response and it fails until the
// type follows.

export type IpResult = {
  ip: string;
  risk_score: number;
  verdict: Verdict;
  signals: {
    is_vpn: boolean;
    is_proxy: boolean;
    is_datacenter: boolean;
    is_tor: boolean;
    recent_abuse: boolean;
  };
  geo: { country: string | null; city: string | null; asn: string | null; isp: string | null };
  /** Named only when the operator's own published list confirms it. */
  vpn_provider: string | null;
  first_seen: string | null;
  times_seen: number;
  abuse_reports: number;
  /** True when served from cache. Cached lookups are never billed. */
  cached: boolean;
  request_id: string;
  processing_time_sec: number;
};

export type EmailResult = {
  email: string;
  /** Provider-normalised form (dots and +tags resolved where applicable). */
  normalized_email: string;
  risk_score: number;
  verdict: Verdict;
  status: string;
  sub_status: string | null;
  /** 0-100. Higher means more likely to accept mail. */
  deliverability_score: number;
  did_you_mean: string | null;
  signals: {
    syntax_valid: boolean;
    mx_found: boolean;
    is_disposable: boolean;
    is_homograph: boolean;
    is_role_account: boolean;
    is_free_provider: boolean;
    is_suspicious_handle: boolean;
    is_tagged: boolean;
    is_risky_tld: boolean;
    has_digital_footprint: boolean;
    /** null = could not be determined, NOT "no". */
    is_catch_all: boolean | null;
    /** null = the domain's age could not be determined, NOT "it is old". */
    is_new_domain: boolean | null;
    /** null = the provider does not answer honestly; never a guess. */
    mailbox_exists: boolean | null;
  };
  domain: string;
  /** null when the TLD publishes no RDAP record. */
  domain_age_days: number | null;
  mx_provider: string | null;
  mx_records: string[];
  first_seen: string | null;
  times_seen: number;
  abuse_reports: number;
  digital_footprint: {
    has_gravatar: boolean;
    gravatar_profile_url: string | null;
    /** null unless a breach source is configured. */
    breach_count: number | null;
    seen_in_breach: boolean | null;
  };
  /** Score before reputation and footprint adjustments. */
  base_risk: number;
  processing_time_sec: number;
};

export type PhoneResult = {
  phone: string;
  risk_score: number;
  verdict: Verdict;
  parse_status: string;
  signals: {
    syntax_valid: boolean;
    is_possible: boolean;
    is_voip: boolean;
    is_premium_rate: boolean;
    is_toll_free: boolean;
    assigned_area_code: boolean;
  };
  number: {
    e164: string | null;
    country: string | null;
    national: string | null;
    international: string | null;
    line_type: string | null;
  };
  processing_time_sec: number;
};

export type DomainResult = {
  domain: string;
  risk_score: number;
  verdict: Verdict;
  signals: {
    resolves: boolean;
    mx_found: boolean;
    has_spf: boolean;
    has_dmarc: boolean;
    is_disposable: boolean;
    is_homograph: boolean;
    is_free_provider: boolean;
    is_risky_tld: boolean;
    /** null = registration date unavailable (no RDAP for that TLD). */
    newly_registered: boolean | null;
  };
  registration: { created_at: string | null; age_days: number | null; registrar: string | null };
  processing_time_sec: number;
};

export type UserResult = {
  risk_score: number;
  verdict: Verdict;
  top_signals: string[];
  components_checked: string[];
  components: Record<string, unknown>;
  request_id: string;
  processing_time_sec: number;
};

export type BatchResult<T> = {
  type: string;
  count: number;
  succeeded: number;
  failed: number;
  billable_lookups: number;
  results: Array<({ input: string } & T) | { input: string; error: string }>;
};

/** A non-2xx from the API. `status` and `code` are what you branch on. */
export class LayerCallError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly requestId?: string;
  constructor(message: string, status: number, code?: string, requestId?: string) {
    super(message);
    this.name = "LayerCallError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
  /** Quota exhausted or spend cap reached — upgrade or raise the cap. */
  get isQuota() {
    return this.status === 402;
  }
  /** Bad or revoked key. */
  get isAuth() {
    return this.status === 401 || this.status === 403;
  }
}

export type ClientOptions = {
  apiKey: string;
  baseUrl?: string;
  /** Per-attempt timeout in ms. Default 5000. */
  timeoutMs?: number;
  /** Retries for 429 and 5xx only. Default 2. */
  retries?: number;
  fetch?: typeof globalThis.fetch;
};

export class LayerCall {
  private readonly key: string;
  private readonly base: string;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private readonly f: typeof globalThis.fetch;

  constructor(opts: ClientOptions | string) {
    const o = typeof opts === "string" ? { apiKey: opts } : opts;
    if (!o.apiKey) throw new Error("LayerCall: apiKey is required.");
    // A key in browser JavaScript is public the moment someone opens devtools,
    // and it bills to your account. Fail loudly rather than let it ship.
    if (typeof window !== "undefined" && !o.baseUrl) {
      throw new Error(
        "LayerCall: this client is server-side only — an API key in a browser is public and billable. " +
          "Call it from your backend, or proxy through your own endpoint.",
      );
    }
    this.key = o.apiKey;
    this.base = (o.baseUrl ?? "https://www.layercall.com").replace(/\/$/, "");
    this.timeoutMs = o.timeoutMs ?? 5000;
    this.retries = o.retries ?? 2;
    this.f = o.fetch ?? globalThis.fetch;
  }

  private async request<T>(path: string, init?: RequestInit & { query?: Record<string, string | number | undefined> }): Promise<T> {
    const url = new URL(this.base + path);
    for (const [k, v] of Object.entries(init?.query ?? {})) {
      if (v !== undefined) url.searchParams.set(k, String(v));
    }

    let lastErr: unknown;
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      try {
        const res = await this.f(url.toString(), {
          ...init,
          headers: {
            "X-Api-Key": this.key,
            "Content-Type": "application/json",
            "User-Agent": "layercall-node/1.0",
            ...(init?.headers ?? {}),
          },
          signal: AbortSignal.timeout(this.timeoutMs),
        });

        const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
        if (res.ok) return body as T;

        // 4xx other than 429 will fail identically on a retry — surface it now
        // rather than spending the caller's latency budget proving it.
        const retryable = res.status === 429 || res.status >= 500;
        const err = new LayerCallError(
          (body.error as string) ?? `HTTP ${res.status}`,
          res.status,
          body.code as string | undefined,
          body.request_id as string | undefined,
        );
        if (!retryable || attempt === this.retries) throw err;
        lastErr = err;
      } catch (e) {
        if (e instanceof LayerCallError && !(e.status === 429 || e.status >= 500)) throw e;
        lastErr = e;
        if (attempt === this.retries) break;
      }
      // Exponential backoff. Deliberately short: this sits on a signup path.
      await new Promise((r) => setTimeout(r, 150 * 2 ** attempt));
    }
    throw lastErr instanceof Error ? lastErr : new Error("LayerCall: request failed");
  }

  scoreIp(ip: string, opts: { strictness?: Strictness } = {}) {
    return this.request<IpResult>("/v1/score/ip", { query: { ip, strictness: opts.strictness } });
  }

  verifyEmail(email: string, opts: { strictness?: Strictness } = {}) {
    return this.request<EmailResult>("/v1/verify/email", { query: { email, strictness: opts.strictness } });
  }

  lookupPhone(phone: string, opts: { country?: string; strictness?: Strictness } = {}) {
    return this.request<PhoneResult>("/v1/lookup/phone", {
      query: { phone, country: opts.country, strictness: opts.strictness },
    });
  }

  scoreDomain(domain: string) {
    return this.request<DomainResult>("/v1/score/domain", { query: { domain } });
  }

  /** Score a whole signup. A hard block on one component is never averaged away. */
  scoreUser(input: {
    ip?: string;
    email?: string;
    phone?: string;
    phone_country?: string;
    domain?: string;
    device_id?: string;
    strictness?: Strictness;
  }) {
    return this.request<UserResult>("/v1/score/user", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  /** Up to 500 values of one type. Each item carries its own error. */
  batch<T = unknown>(
    type: "ip" | "email" | "phone" | "domain",
    items: string[],
    opts: { strictness?: Strictness; phone_country?: string } = {},
  ) {
    return this.request<BatchResult<T>>("/v1/batch", {
      method: "POST",
      body: JSON.stringify({ type, items, ...opts }),
    });
  }
}

export default LayerCall;

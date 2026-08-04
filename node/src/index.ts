/**
 * Official LayerCall client.
 *
 * Zero dependencies and one file on purpose. A trust check sits on the signup
 * path, which is the worst place in an application to introduce a transitive
 * dependency tree, a supply-chain surface, or a version conflict with whatever
 * the host app already uses.
 */

export type Verdict = "allow" | "review" | "block";

/**
 * Present only on responses produced by a test key (`tl_test_`).
 *
 * Test keys return synthetic data — scores and signals are derived from the
 * value you sent, not from anything we know about it. Shapes, error codes and
 * your custom rules behave exactly as in production, so integration tests are
 * valid; the numbers are not. Branch on `test_mode` if you need to assert that
 * a suite is pointed at a test key rather than a live one.
 *
 * Absent on live responses, so `result.test_mode` is a safe truthiness check.
 * See https://www.layercall.com/docs/test-mode
 */
export type TestModeMarkers = {
  /** "test" on synthetic responses; absent on live ones. */
  mode?: "test";
  /** True on synthetic responses; absent on live ones. */
  test_mode?: true;
  /** Human-readable explanation of why the values are fabricated. */
  test_mode_note?: string;
};

/** 0 lenient · 1 balanced (default) · 2 strict · 3 paranoid. */
export type Strictness = 0 | 1 | 2 | 3;

/**
 * What kind of thing made this request.
 *
 * Branch on `proven` rather than on `type` when the difference between evidence
 * and proof matters. It is true for exactly one thing — a Web Bot Auth
 * signature that verified, which is arithmetic and has no false-positive rate.
 * Everything else here is inference that a capable adversary can defeat.
 *
 * There is deliberately no "human" value: a capable AI agent driving a real
 * browser passes every human check, so `likely_human` means "nothing here looks
 * automated", which is a statement about our evidence and not about your
 * visitor.
 */
export type ActorType =
  | "verified_agent"
  | "impersonated_agent"
  | "automation"
  | "likely_human"
  | "unknown";

export type Actor = {
  type: ActorType;
  /** True only for a verified cryptographic signature. */
  proven: boolean;
  basis: "signature" | "device_signals" | "none";
  /** Named only when a signature named it — never guessed from a user agent. */
  operator: string | null;
  /** "fetcher" = a person asked for this. "crawler" = nobody did. */
  trigger: string | null;
  detail: string;
};

/**
 * Patterns across values, which no single value can show.
 *
 * A null means we do not know, never zero. Reporting an unavailable count as 0
 * would read as "this device has never been seen with any other address",
 * which is the strongest exonerating claim this layer can make.
 */
export type Linkage = {
  device_email_count: number | null;
  email_device_count: number | null;
  email_ip_count: number | null;
  /** Scoped to the /24: rotating inside a subnet is the cheapest evasion there is. */
  subnet_rate_1h: number | null;
  domain_rate_1h: number | null;
};

export type AgentDecision = "allow" | "deny" | "review";

/** A decision, not a score. Which rule decided is the actionable part. */
export type AgentAuthorization = {
  decision: AgentDecision;
  /** "rule[N]" for your own policy, or the built-in default that applied. */
  matched: string;
  reason: string;
  verified: boolean;
  host: string | null;
  trigger: string | null;
  publishes_card: boolean;
};

/** One rule in your agent policy. Evaluated in order; first match wins. */
export type AgentRule = {
  /** Signature-Agent host, e.g. "chatgpt.com". Omit for any agent. */
  agent?: string;
  trigger?: "fetcher" | "crawler";
  purpose?: string;
  /** Literal path prefix, never a pattern. */
  path?: string;
  methods?: string[];
  max_per_hour?: number;
  action: AgentDecision;
  reason?: string;
};

/** Whether a score turned out to be right. See LayerCall#reportOutcome. */
export type Outcome = "fraud" | "legitimate";

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

export type IpResult = TestModeMarkers & {
  ip: string;
  risk_score: number;
  verdict: Verdict;
  signals: {
    is_vpn: boolean;
    is_proxy: boolean;
    is_datacenter: boolean;
    is_tor: boolean;
    recent_abuse: boolean;
    /**
     * Inside a netblock Spamhaus DROP lists as hijacked or criminal-controlled.
     * A separate dimension from VPN/datacenter/Tor: stolen space looks like
     * nothing in particular, which is precisely why it gets stolen.
     */
    is_hijacked_netblock: boolean;
    /** RFC1918 or reserved — usually a misconfiguration on your side. */
    is_private_or_reserved?: boolean;
  };
  /** Attribution for is_hijacked_netblock; null when it did not fire. */
  hijacked_source?: string | null;
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

export type EmailResult = TestModeMarkers & {
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
    /** Domain publishes an SPF record. */
    has_spf: boolean;
    /** Domain publishes a DMARC policy. */
    has_dmarc: boolean;
    /** null = the provider does not answer honestly; never a guess. */
    mailbox_exists: boolean | null;
    /**
     * Which kind of "unknown" you have — a bare null cannot tell them apart.
     * "catch_all" means the domain accepts mail for addresses that do not
     * exist, so nobody can ever verify it. "pending" means the answer will be
     * there next time.
     */
    mailbox_status: "verified" | "catch_all" | "pending" | "unsupported" | "unavailable";
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
  // No base_risk here. It was declared as a required number, but the API only
  // emitted it on a cache hit — an internal field that leaked through a spread
  // of the cache entry. TypeScript users were promised a number that was
  // undefined on any cold lookup. The leak is fixed in lib/email.ts; the field
  // is internal and stays unexposed.
  processing_time_sec: number;
  /** Quote this to reportOutcome() to tell us whether the score was right. */
  request_id: string;
};

export type PhoneResult = TestModeMarkers & {
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
    /** Reserved for fiction (555-0100..0199) and never assignable. */
    is_fictional: boolean | null;
  };
  number: {
    e164: string | null;
    country: string | null;
    national: string | null;
    international: string | null;
    line_type: string | null;
  };
  processing_time_sec: number;
  /** Quote this to reportOutcome() to tell us whether the score was right. */
  request_id: string;
};

export type DomainResult = TestModeMarkers & {
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
  /** Quote this to reportOutcome() to tell us whether the score was right. */
  request_id: string;
};

export type UserResult = TestModeMarkers & {
  risk_score: number;
  verdict: Verdict;
  /** What kind of thing this is, as opposed to what to do about it. */
  actor: Actor;
  /** Cross-value patterns. Reported today; they do not yet move the score. */
  linkage: Linkage;
  /** Present only when you passed `agent`. A denied agent forces verdict=block. */
  agent?: AgentAuthorization;
  top_signals: string[];
  components_checked: string[];
  components: Record<string, unknown>;
  request_id: string;
  processing_time_sec: number;
};

export type DeviceResult = TestModeMarkers & {
  device_id: string;
  risk_score: number;
  verdict: Verdict;
  bot_probability: number;
  signals: {
    is_bot: boolean;
    is_automated: boolean;
    is_headless: boolean;
    timezone_mismatch: boolean;
    repeat_device: boolean;
  };
  first_seen: string | null;
  times_seen: number;
  abuse_reports: number;
};

/** Web Bot Auth. `verified` is cryptographic proof, not an inference. */
export type AgentResult = TestModeMarkers & {
  verified: boolean;
  /** e.g. "https://chatgpt.com". Present even when verification fails. */
  agent: string | null;
  keyid: string | null;
  /** "ai", "search", … self-asserted by the agent's directory. */
  purpose: string | null;
  /** Why it failed. null when verified. */
  reason: string | null;
  expires_in: number | null;
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

  /**
   * Score a whole signup, in one call.
   *
   * Returns risk_score and verdict, plus `actor` (what kind of thing this is,
   * with `proven` true only for a verified signature) and `linkage` (patterns
   * across values that no single value can show). Pass `agent` to get an
   * authorization decision in the same call; a denied agent forces the verdict
   * to block, because that is your own policy.
   *
   * A block on any single component floors the combined score at review, so one
   * definitive red flag is never averaged away by four clean ones. It stops at
   * review rather than block on purpose: one certain component is not a certain
   * signup. Raise strictness to 2 if you want that floor to land on block.
   */
  scoreUser(input: {
    ip?: string;
    email?: string;
    phone?: string;
    phone_country?: string;
    domain?: string;
    /** Fingerprint from /fp.js. */
    device_id?: string;
    /** Browser characteristics from /fp.js — needed for bot scoring. */
    device_signals?: Record<string, unknown>;
    /** Automation markers from /fp.js. */
    device_automation?: Record<string, unknown>;
    /**
     * The signed request an AI agent made to YOU, if one did.
     *
     * The Web Bot Auth signature covers the method, URL and headers the agent
     * sent, so none of it can be inferred — pass them exactly as they arrived.
     * Omit for an ordinary signup and nothing about the response changes.
     */
    agent?: { method?: string; url: string; headers: Record<string, string> };
    strictness?: Strictness;
  }) {
    return this.request<UserResult>("/v1/score/user", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  /**
   * Score a device fingerprint from /fp.js.
   *
   * POST, never GET: a device id in a URL lands in access logs and Referer
   * headers, and that is a tracking identifier.
   */
  scoreDevice(input: {
    device_id: string;
    ip?: string;
    signals?: Record<string, unknown>;
    automation?: Record<string, unknown>;
  }) {
    return this.request<DeviceResult>("/v1/score/device", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  /**
   * Verify a Web Bot Auth signature — proof of WHICH agent is calling.
   *
   * Pass the request the agent made to YOU: the signature covers its method,
   * authority and path, so none of it can be inferred from our side.
   *
   * The only check here that proves rather than infers, so there is no score
   * and no verdict. What to do about a verified agent is your policy: an
   * assistant acting for a real user is usually welcome, a scraper usually is
   * not, and both may be correctly signed.
   */
  verifyAgent(input: { method?: string; url: string; headers: Record<string, string> }) {
    return this.request<AgentResult>("/v1/verify/agent", {
      method: "POST",
      body: JSON.stringify({ method: input.method ?? "GET", ...input }),
    });
  }

  /**
   * Report a value as confirmed fraud, feeding the shared reputation network.
   *
   * Live keys only — a test key is refused, because test traffic must never
   * teach the network something a suite invented.
   */
  /**
   * Should this agent be allowed to do this, here?
   *
   * verifyAgent() answers "who is this" and stops. This applies your policy to
   * the answer and returns a decision with the rule that made it. Use
   * scoreUser({ agent }) instead when there is a signup identity to score
   * alongside it — one call does both.
   */
  authorizeAgent(input: { method?: string; url: string; headers: Record<string, string> }) {
    return this.request<AgentAuthorization & { agent: Record<string, unknown> }>(
      "/v1/agent/authorize",
      { method: "POST", body: JSON.stringify(input) },
    );
  }

  /** Read your agent policy. Free. */
  getAgentPolicy() {
    return this.request<{ rules: AgentRule[]; updated_at: string | null }>("/v1/agent/policy");
  }

  /**
   * Replace your agent policy. Free.
   *
   * Rules are evaluated in order and the first match wins. An empty policy is
   * not an open door: the defaults still deny an unverifiable signature and
   * refuse a self-declared crawler attempting to change state.
   */
  setAgentPolicy(rules: AgentRule[]) {
    return this.request<{ saved: number; rules: AgentRule[] }>("/v1/agent/policy", {
      method: "PUT",
      body: JSON.stringify({ rules }),
    });
  }

  /**
   * Tell us whether a score was right.
   *
   * Free, and the only way either of us finds out whether the thresholds suit
   * your traffic. A "fraud" label also raises the abuse counters on every value
   * in that score across the whole network, so your confirmed loss protects the
   * next customer immediately.
   *
   * Pass the request_id from the score you are reporting on. Accepts one or an
   * array of up to 500 — a day of chargebacks is a list, not 500 requests.
   */
  reportOutcome(
    input: { request_id: string; outcome: Outcome } | Array<{ request_id: string; outcome: Outcome }>,
  ) {
    return this.request<{
      recorded: number;
      not_found: number;
      results: Array<{
        request_id: string;
        status: "recorded" | "relabelled" | "not_found" | "invalid" | "unavailable";
        our_score?: number;
        our_verdict?: Verdict;
        /** True when we said allow and you saw fraud, or we said block and it was fine. */
        disagreement?: boolean;
      }>;
    }>("/v1/outcome", { method: "POST", body: JSON.stringify(input) });
  }

  report(kind: "ip" | "email" | "phone" | "domain" | "device", value: string, reason?: string) {
    return this.request<{ reported: number; results: Array<{ kind: string; abuse_reports: number }> }>(
      "/v1/report",
      { method: "POST", body: JSON.stringify({ kind, value, reason }) },
    );
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

/**
 * Official LayerCall client.
 *
 * Zero dependencies and one file on purpose. A trust check sits on the signup
 * path, which is the worst place in an application to introduce a transitive
 * dependency tree, a supply-chain surface, or a version conflict with whatever
 * the host app already uses.
 */

/**
 * Kept in step with package.json by sdk-callable.test.mjs.
 *
 * Not read from package.json at runtime: this file is bundled by everything
 * from webpack to esbuild to Bun, and a require("../package.json") is the one
 * line guaranteed to break in some of them. A constant plus a test that fails
 * the build on drift is the version of this that cannot silently rot — which
 * the previous value, a hardcoded "1.0" that no release since 1.0.0 has been
 * true of, demonstrates. Every Node call was reporting a version we shipped
 * years of changes ago, so the one field that says which client a customer
 * runs was useless for exactly the question it exists to answer.
 */
const VERSION = "1.2.11";

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

/*
 * Declared once so a new result type cannot be written without it. Kept out
 * of the doc comment below on purpose: that one is what a customer's editor
 * shows, and this history is ours.
 *
 * These three drifted apart because each result type listed them by hand.
 * Measured against the live API on 10 September 2026: billable_lookups was on
 * 2 of 8 types, request_id on 6, processing_time_sec on 5 - while the API
 * returns all three on every scoring endpoint. Six types were missing
 * billable_lookups, and DeviceResult and AgentResult were missing all three.
 *
 * That mattered beyond tidiness. /pricing sells billable_lookups as the reason
 * "you never have to guess" about spend, and both competitor comparison pages
 * cite it as a checkable advantage - so the one thing the marketing points at
 * was a compile error for any TypeScript customer who tried to read it.
 *
 * It had happened before: a fix on 31 August added it to UserResult and audited
 * the class, a change on 3 September rolled the field out to every endpoint,
 * and the types fell behind again. A list maintained by memory drifts; an
 * intersection cannot. Adding a result type now inherits these by construction.
 */
/** What every scored response carries: what it cost, its id, and how long it took. */
export type ScoredEnvelope = {
  /** Billable lookups this call consumed. Cached and test-mode calls are 0. */
  billable_lookups: number;
  /** Server-side id for this request. Quote it in a support message. */
  request_id: string;
  /** Wall-clock seconds spent producing this answer. */
  processing_time_sec: number;
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

export type IpResult = TestModeMarkers & ScoredEnvelope & {
  /**
   * Signals that could NOT be measured on this request, omitted entirely when
   * everything answered.
   *
   * A fraud answer that says "clean" and one that says "we could not look"
   * used to be the same bytes on the wire. Branch on this when a false
   * negative matters: `if (res.signals_unavailable) …` — the key is absent on
   * the happy path, so it never changes the shape you already parse.
   *
   * IT IS NOT ALWAYS AN OUTAGE, AND A FAIL-CLOSED BRANCH WILL NOTICE.
   *
   * Two different facts arrive under this one key, deliberately, because for
   * you they have the same consequence — a signal you can see in the response
   * was not measured, so a clean answer is not evidence of cleanliness:
   *
   *   something was down        transient. It clears.
   *   nothing covers this input permanent for that input. It does not clear.
   *
   * The second is not hypothetical and it is not rare. Five of the IP feeds
   * are IPv4-only, so EVERY IPv6 address carries ip_reputation, cloud_ranges,
   * hijacked_ranges, abuse_reports and vpn_providers here, on every request,
   * forever. Mobile carriers are heavily IPv6, so that is ordinary signup
   * traffic — and an integration that sends everything with this key present
   * to manual review will send a large and permanent share of its signups
   * there.
   *
   * So: treat it as "this particular signal is unproven", not as "LayerCall is
   * degraded". Deciding per NAME is the robust reading — if you are screening
   * for Tor and `tor` is not in the list, the Tor check ran.
   */
  signals_unavailable?: string[];
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

export type EmailResult = TestModeMarkers & ScoredEnvelope & {
  /**
   * Signals that could NOT be measured on this request, omitted entirely when
   * everything answered.
   *
   * A fraud answer that says "clean" and one that says "we could not look"
   * used to be the same bytes on the wire. Branch on this when a false
   * negative matters: `if (res.signals_unavailable) …` — the key is absent on
   * the happy path, so it never changes the shape you already parse.
   *
   * IT IS NOT ALWAYS AN OUTAGE, AND A FAIL-CLOSED BRANCH WILL NOTICE.
   *
   * Two different facts arrive under this one key, deliberately, because for
   * you they have the same consequence — a signal you can see in the response
   * was not measured, so a clean answer is not evidence of cleanliness:
   *
   *   something was down        transient. It clears.
   *   nothing covers this input permanent for that input. It does not clear.
   *
   * The second is not hypothetical and it is not rare. Five of the IP feeds
   * are IPv4-only, so EVERY IPv6 address carries ip_reputation, cloud_ranges,
   * hijacked_ranges, abuse_reports and vpn_providers here, on every request,
   * forever. Mobile carriers are heavily IPv6, so that is ordinary signup
   * traffic — and an integration that sends everything with this key present
   * to manual review will send a large and permanent share of its signups
   * there.
   *
   * So: treat it as "this particular signal is unproven", not as "LayerCall is
   * degraded". Deciding per NAME is the robust reading — if you are screening
   * for Tor and `tor` is not in the list, the Tor check ran.
   */
  signals_unavailable?: string[];
  /**
   * Served from cache, and therefore not billed.
   *
   * The API gained this on email, phone and domain when a billing bug was
   * fixed: only the IP scorer had ever set it, so cached lookups on the other
   * three were charged despite the docs promising they were free. The SDK types
   * did not follow, so TypeScript users could not reach a field the API was
   * already returning — and the contract test caught it.
   */
  cached: boolean;
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
    /*
     * Returned by the API and asserted in the scoring invariants since it
     * shipped, but missing from this type until 1.2.3, so TypeScript callers
     * had to cast to reach it. And it was typed `boolean` while the API could
     * already answer null on a slow request, so the type was a promise the
     * server had never made.
     */
    /**
     * Domain serves a website.
     *
     * A real business almost always has one; a domain registered purely to
     * receive signup confirmations often does not. Weak on its own — plenty of
     * legitimate domains are mail-only — which is why it is a signal you can
     * read rather than something that moves the score by itself.
     *
     * null means we did not look, and it is the common case: the check is
     * skipped for any domain publishing SPF or DMARC, which is most of them.
     * Branch on `=== false` for "no site", never on falsiness.
     */
    has_website: boolean | null;
    /** null = the provider does not answer honestly; never a guess. */
    mailbox_exists: boolean | null;
    /**
     * Which kind of "unknown" you have — a bare null cannot tell them apart.
     * "catch_all" means the domain accepts mail for addresses that do not
     * exist, so nobody can ever verify it. "pending" means the answer will be
     * there next time.
     */
    /**
     * Which kind of "unknown" you have, because a bare null cannot tell them
     * apart and they call for opposite reactions.
     *
     * `unknown` is the newest and was the API's for a long time before it was
     * ever declared: it is returned when the request's own time budget runs out
     * before the mailbox stage, and a cast in the server let it past a union
     * that listed only the other five. If you switch exhaustively on this, that
     * is the case you were never told about.
     */
    mailbox_status:
      | "verified"
      | "catch_all"
      | "pending"
      | "unsupported"
      | "unavailable"
      | "unknown";
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

export type PhoneResult = TestModeMarkers & ScoredEnvelope & {
  /* Added to phone and domain on 2026-08-19, when both joined the network:
     until then a customer could label either through reportOutcome() and it
     credited nothing. */
  /**
   * Reputation-network history, as on IpResult and EmailResult.
   *
   * abuse_reports is the one to branch on — it counts confirmed fraud reports
   * from across the network, not lookups. times_seen feeds the score for a
   * phone (one number, so repetition is signal) and deliberately does NOT for a
   * domain (one domain is a category, so repetition is popularity).
   */
  first_seen: string | null;
  times_seen: number;
  abuse_reports: number;
  /**
   * Served from cache, and therefore not billed.
   *
   * The API gained this on email, phone and domain when a billing bug was
   * fixed: only the IP scorer had ever set it, so cached lookups on the other
   * three were charged despite the docs promising they were free. The SDK types
   * did not follow, so TypeScript users could not reach a field the API was
   * already returning — and the contract test caught it.
   */
  cached: boolean;
  phone: string;
  risk_score: number;
  verdict: Verdict;
  /**
   * Why the number did not parse, and in one case how to fix it.
   *
   * This was typed `string`, so a TypeScript developer got no autocomplete and
   * no clue the four values existed — the types were generated from live
   * responses, which only ever showed "ok", so the generator flattened the
   * enum away. `country_required` is the single most actionable thing the
   * phone product says: resend with a country and it will work.
   */
  parse_status: "ok" | "country_required" | "impossible" | "invalid_pattern";
  signals: {
    syntax_valid: boolean;
    is_possible: boolean;
    /**
     * null where the country's numbering plan reserves no VoIP range (the US,
     * India, Germany and others), or the number is only "fixed line or
     * mobile": unknown, not "no".
     */
    is_voip: boolean | null;
    is_premium_rate: boolean;
    is_toll_free: boolean;
    /** NANP only: null outside +1, where there are no area codes to check. */
    assigned_area_code: boolean | null;
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

export type DomainResult = TestModeMarkers & ScoredEnvelope & {
  /* Added to phone and domain on 2026-08-19, when both joined the network:
     until then a customer could label either through reportOutcome() and it
     credited nothing. */
  /**
   * Reputation-network history, as on IpResult and EmailResult.
   *
   * abuse_reports is the one to branch on — it counts confirmed fraud reports
   * from across the network, not lookups. times_seen feeds the score for a
   * phone (one number, so repetition is signal) and deliberately does NOT for a
   * domain (one domain is a category, so repetition is popularity).
   */
  first_seen: string | null;
  times_seen: number;
  abuse_reports: number;
  /**
   * Signals that could NOT be measured on this request, omitted entirely when
   * everything answered.
   *
   * A fraud answer that says "clean" and one that says "we could not look"
   * used to be the same bytes on the wire. Branch on this when a false
   * negative matters: `if (res.signals_unavailable) …` — the key is absent on
   * the happy path, so it never changes the shape you already parse.
   *
   * IT IS NOT ALWAYS AN OUTAGE, AND A FAIL-CLOSED BRANCH WILL NOTICE.
   *
   * Two different facts arrive under this one key, deliberately, because for
   * you they have the same consequence — a signal you can see in the response
   * was not measured, so a clean answer is not evidence of cleanliness:
   *
   *   something was down        transient. It clears.
   *   nothing covers this input permanent for that input. It does not clear.
   *
   * The second is not hypothetical and it is not rare. Five of the IP feeds
   * are IPv4-only, so EVERY IPv6 address carries ip_reputation, cloud_ranges,
   * hijacked_ranges, abuse_reports and vpn_providers here, on every request,
   * forever. Mobile carriers are heavily IPv6, so that is ordinary signup
   * traffic — and an integration that sends everything with this key present
   * to manual review will send a large and permanent share of its signups
   * there.
   *
   * So: treat it as "this particular signal is unproven", not as "LayerCall is
   * degraded". Deciding per NAME is the robust reading — if you are screening
   * for Tor and `tor` is not in the list, the Tor check ran.
   */
  signals_unavailable?: string[];
  /**
   * Served from cache, and therefore not billed.
   *
   * The API gained this on email, phone and domain when a billing bug was
   * fixed: only the IP scorer had ever set it, so cached lookups on the other
   * three were charged despite the docs promising they were free. The SDK types
   * did not follow, so TypeScript users could not reach a field the API was
   * already returning — and the contract test caught it.
   */
  cached: boolean;
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

export type UserResult = TestModeMarkers & ScoredEnvelope & {
  /**
   * Signals that could NOT be measured on this request, omitted entirely when
   * everything answered.
   *
   * A fraud answer that says "clean" and one that says "we could not look"
   * used to be the same bytes on the wire. Branch on this when a false
   * negative matters: `if (res.signals_unavailable) …` — the key is absent on
   * the happy path, so it never changes the shape you already parse.
   *
   * IT IS NOT ALWAYS AN OUTAGE, AND A FAIL-CLOSED BRANCH WILL NOTICE.
   *
   * Two different facts arrive under this one key, deliberately, because for
   * you they have the same consequence — a signal you can see in the response
   * was not measured, so a clean answer is not evidence of cleanliness:
   *
   *   something was down        transient. It clears.
   *   nothing covers this input permanent for that input. It does not clear.
   *
   * The second is not hypothetical and it is not rare. Five of the IP feeds
   * are IPv4-only, so EVERY IPv6 address carries ip_reputation, cloud_ranges,
   * hijacked_ranges, abuse_reports and vpn_providers here, on every request,
   * forever. Mobile carriers are heavily IPv6, so that is ordinary signup
   * traffic — and an integration that sends everything with this key present
   * to manual review will send a large and permanent share of its signups
   * there.
   *
   * So: treat it as "this particular signal is unproven", not as "LayerCall is
   * degraded". Deciding per NAME is the robust reading — if you are screening
   * for Tor and `tor` is not in the list, the Tor check ran.
   */
  signals_unavailable?: string[];
  risk_score: number;
  verdict: Verdict;
  /**
   * One sentence describing the decision, e.g.
   * "Blocked (100/100) — Tor exit node, disposable domain and machine-generated handle."
   *
   * The text for a Slack alert, a review ticket, or a log line. Built from the
   * same top_signals as the rest of the response, so it can never disagree with
   * them.
   */
  summary: string;
  /** What kind of thing this is, as opposed to what to do about it. */
  actor: Actor;
  /** Cross-value patterns. Reported today; they do not yet move the score. */
  linkage: Linkage;
  /** Present only when you passed `agent`. A denied agent forces verdict=block. */
  agent?: AgentAuthorization;
  top_signals: string[];
  components_checked: string[];
  components: Record<string, unknown>;
  /**
   * What this call actually costs you, in credits.
   *
   * NOT `components_checked.length`. A unified call bills one credit per
   * component, so a signup scored on IP + email + phone + domain is four, and
   * a developer modelling spend off "one credit = one lookup" is out by up to
   * 5x. Cached components are refunded and already subtracted here, so this is
   * the number that reaches the bill rather than the number of things looked
   * at — which also means it can be lower than `components_checked.length`.
   *
   * `BatchResult` has carried the same field since it was written; this type
   * was the one that fell behind, and the SDK contract check against the live
   * API is what noticed.
   */
  billable_lookups: number;
  request_id: string;
  processing_time_sec: number;
};

export type DeviceResult = TestModeMarkers & ScoredEnvelope & {
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
export type AgentResult = TestModeMarkers & ScoredEnvelope & {
  verified: boolean;
  /** e.g. "https://chatgpt.com". Present even when verification fails. */
  agent: string | null;
  keyid: string | null;
  /** "ai", "search", … self-asserted by the agent's directory. */
  purpose: string | null;
  /** Why it failed. null when verified. */
  reason: string | null;
  expires_in: number | null;
  /* Returned unconditionally by the endpoint and by the test fixture, and it
     was undeclared here, so `result.replay_protection` failed to compile for a
     TypeScript customer until the 13 September 2026 audit. */
  /** How replay is prevented — "signature-window" today. */
  replay_protection: string;
  /** Where the verification scheme is documented. */
  docs: string;
};

/*
 * INTERSECTS TestModeMarkers, because a test-mode batch carries them.
 *
 * Verified against production on 13 September 2026 with a tl_test_ key: POST
 * /v1/batch returns mode, test_mode and test_mode_note alongside its counters.
 * They were undeclared here, so a customer could not check whether they were
 * still on a test key from a batch response — the one call most likely to be
 * the first thing they run at volume.
 *
 * It does NOT intersect ScoredEnvelope: a batch is not shaped like a scored
 * response. Verified 10 September 2026 — it returns processing_time_sec but no
 * request_id, so inheriting the envelope would promise a field that never
 * arrives.
 */
/** One batch call: its counters, a result or error per input, and on a test key the test-mode markers. */
export type BatchResult<T> = TestModeMarkers & {
  type: string;
  count: number;
  succeeded: number;
  failed: number;
  billable_lookups: number;
  /* Declared here rather than inherited from ScoredEnvelope because a batch is
     NOT shaped like a scored response: verified against the live endpoint on 10
     September 2026, POST /v1/batch returns processing_time_sec but no
     request_id, so intersecting the envelope would have promised a field that
     never arrives. */
  /** Wall-clock seconds for the whole batch. */
  processing_time_sec: number;
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

export type RuleAction = "allow" | "block";
export type RuleKind = "ip" | "cidr" | "email" | "domain" | "phone" | "asn";

export type Rule = {
  id: string;
  action: RuleAction;
  kind: RuleKind;
  value: string;
  created_at: string;
};

export type ClientOptions = {
  apiKey: string;
  baseUrl?: string;
  /* This was 5000, which is SHORTER than every endpoint's server-side budget:
     /v1/score/ip carries maxDuration 25, /v1/verify/email and /v1/score/user
     15, /v1/batch 300. A cold start or a slow feed refresh therefore outlived
     the client's patience routinely, and the abandoned request kept running —
     finishing, metering a billable lookup, and returning to nobody. */
  /**
   * Per-attempt timeout in ms. Default 30000, longer than any endpoint's own
   * ceiling, so a slow answer is not abandoned after it has been billed.
   *
   * Set it lower if a signup path cannot wait; just pair it with `retries: 0`,
   * or you are paying for answers you have already decided not to read.
   */
  timeoutMs?: number;
  /**
   * Retries for 429 and 5xx only. Default 2.
   *
   * A timeout is NOT retried, whatever this is set to. See the loop below.
   */
  retries?: number;
  fetch?: typeof globalThis.fetch;
};

export class LayerCall {
  private readonly key: string;
  private readonly base: string;
  private readonly timeoutMs: number;
  private readonly batchTimeoutMs: number;
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
    this.timeoutMs = o.timeoutMs ?? 30_000;
    /**
     * A FLOOR, not a fallback — and the comment above was already describing
     * the floor while the code did the opposite.
     *
     * `o.timeoutMs ?? 300_000` uses the caller's general timeout for batches
     * whenever they set one. So a developer following this SDK's own docstring
     * advice to set a low timeout on a signup path — say 3 seconds — got a
     * 3-second timeout on /v1/batch too, and every batch was abandoned
     * mid-flight. Server-side that used to mean it was billed in full anyway;
     * that hole is now closed, but the client should never have been aiming a
     * signup-path timeout at a 500-item batch in the first place.
     *
     * The Python SDK has always had this right: `max(timeout, 300.0)`. The two
     * clients disagreed, and the more popular one was the wrong one.
     *
     * Only helps NEW installs — an existing lockfile pins the old version
     * forever, which is why the server-side abandonment check is the fix that
     * actually matters. See lib/sdkIsNotADeliveryMechanism in the notes.
     */
    this.batchTimeoutMs = Math.max(o.timeoutMs ?? 0, 300_000);
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
            "User-Agent": `layercall-node/${VERSION}`,
            ...(init?.headers ?? {}),
          },
          signal: AbortSignal.timeout(path === "/v1/batch" ? this.batchTimeoutMs : this.timeoutMs),
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
        /**
         * A TIMEOUT IS NOT EVIDENCE THAT THE SERVER FAILED.
         *
         * It only says we stopped waiting. The request very likely arrived and
         * is still being processed — and it will finish, meter a billable
         * lookup, and return to nobody. Retrying it does not recover that
         * lookup, it buys a second one. With the old 5s default against a
         * 25-second endpoint budget, one logical call became three billable
         * ones and the caller still got an error.
         *
         * A connection-level failure is different: refused, reset or DNS means
         * the request never reached us, so a retry is free and worth making.
         * Those still retry below.
         */
        const name = (e as { name?: string })?.name;
        if (name === "TimeoutError" || name === "AbortError") throw e;
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

  /**
   * @param opts.waitForMailbox Block until the SMTP mailbox probe finishes,
   * rather than returning `mailbox_status: "pending"`.
   *
   * This is the documented remedy for a pending mailbox, and it was reachable
   * only by hand-writing the HTTP call: the docs told a customer to pass
   * `?wait_for_mailbox=true` and the recommended client had no way to. Costs
   * 2-10 seconds on a cache miss, which is why it is opt-in.
   */
  verifyEmail(email: string, opts: { strictness?: Strictness; waitForMailbox?: boolean } = {}) {
    return this.request<EmailResult>("/v1/verify/email", {
      query: {
        email,
        strictness: opts.strictness,
        wait_for_mailbox: opts.waitForMailbox ? "true" : undefined,
      },
    });
  }

  lookupPhone(phone: string, opts: { country?: string; strictness?: Strictness } = {}) {
    return this.request<PhoneResult>("/v1/lookup/phone", {
      query: { phone, country: opts.country, strictness: opts.strictness },
    });
  }

  scoreDomain(domain: string, opts: { strictness?: Strictness } = {}) {
    return this.request<DomainResult>("/v1/score/domain", {
      query: { domain, strictness: opts.strictness },
    });
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
   *
   * `strictness` goes in the query string even though the rest is a body:
   * every route reads it from the URL, POST ones included. It is destructured
   * out of `input` rather than added to it, so it cannot end up in the JSON
   * body where the route would not look for it.
   */
  scoreDevice(input: {
    device_id: string;
    ip?: string;
    signals?: Record<string, unknown>;
    automation?: Record<string, unknown>;
    strictness?: Strictness;
  }) {
    const { strictness, ...body } = input;
    return this.request<DeviceResult>("/v1/score/device", {
      method: "POST",
      query: { strictness },
      body: JSON.stringify(body),
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

  /**
   * Report a value as confirmed fraud, feeding the shared reputation network.
   *
   * Live keys only — a test key is refused, because test traffic must never
   * teach the network something a suite invented.
   *
   * "device" is deliberately absent from `kind`: /v1/report accepts ip, email,
   * domain and phone, and 400s on anything else. Offering it in autocomplete
   * meant the type suggested a call that could only ever fail — the one thing
   * a typed client exists to prevent.
   */
  // The block above used to sit two doc comments deep over authorizeAgent,
  // where only the second one binds. So the warning that this method refuses
  // test keys shipped in dist/index.d.ts attached to nothing, and report()
  // itself had no hover text at all: a developer wrote it into a test suite
  // with a test key and got an unexplained rejection.
  report(kind: "ip" | "email" | "phone" | "domain", value: string, reason?: string) {
    return this.request<{ reported: number; results: Array<{ kind: string; abuse_reports: number }> }>(
      "/v1/report",
      { method: "POST", body: JSON.stringify({ kind, value, reason }) },
    );
  }

  /**
   * CUSTOM RULES — your lists always win.
   *
   * One of the nine products on the homepage, three endpoints, and until now
   * no method in either SDK for any of them. A customer following our own
   * advice to use the SDK found a promoted feature reachable only by
   * hand-writing HTTP, and would reasonably conclude it was unfinished.
   *
   * A rule's kind (ip, cidr, email, domain, phone, asn) is detected from the
   * value unless you force it.
   */
  listRules() {
    return this.request<{ count: number; rules: Rule[] }>("/v1/rules");
  }

  /**
   * Add one rule or many. Re-adding an existing rule is idempotent.
   *
   * @param values A single value or a list of them.
   * @param opts.kind Force the kind rather than detecting it per value.
   */
  addRules(
    action: RuleAction,
    values: string | string[],
    opts: { kind?: RuleKind } = {},
  ) {
    return this.request<{ added: number; skipped: Array<{ value: string; reason: string }>; rules: Rule[] }>(
      "/v1/rules",
      {
        method: "POST",
        body: JSON.stringify({
          action,
          values: Array.isArray(values) ? values : [values],
          ...(opts.kind ? { kind: opts.kind } : {}),
        }),
      },
    );
  }

  /** Remove one rule by id. */
  deleteRule(id: string) {
    return this.request<{ deleted: boolean; id: string }>(`/v1/rules/${encodeURIComponent(id)}`, {
      method: "DELETE",
    });
  }

  /**
   * Remove EVERY rule on the account.
   *
   * `confirm: true` is required by the API and deliberately not defaulted
   * here — the whole point of the flag is that it cannot happen by accident,
   * and an SDK that fills it in for you removes the guard.
   */
  clearRules(opts: { confirm: boolean }) {
    if (!opts.confirm) {
      throw new Error("LayerCall: clearRules deletes every rule on the account — pass { confirm: true }.");
    }
    return this.request<{ deleted: number }>("/v1/rules", {
      method: "DELETE",
      query: { confirm: "true" },
    });
  }

  /** Import rules from pasted text — one value per line, or CSV. */
  importRules(action: RuleAction, text: string, opts: { kind?: RuleKind } = {}) {
    return this.request<{ added: number; skipped: Array<{ value: string; reason: string }> }>(
      "/v1/rules/import",
      { method: "POST", body: JSON.stringify({ action, text, ...(opts.kind ? { kind: opts.kind } : {}) }) },
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

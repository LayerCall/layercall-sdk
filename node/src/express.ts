import { LayerCall, type UserResult, type Verdict } from "./index.js";

// Express middleware.
//
// Structural types rather than @types/express: this package has zero runtime
// AND zero type dependencies, so it installs the same whether the app is on
// Express 4, Express 5, Connect, or anything else that speaks (req, res, next).

type Req = {
  method?: string;
  ip?: string;
  path?: string;
  body?: Record<string, unknown> | undefined;
  headers: Record<string, string | string[] | undefined>;
  socket?: { remoteAddress?: string };
  [key: string]: unknown;
};
type Res = { [key: string]: unknown };
type Next = (err?: unknown) => void;

/** What the middleware attaches to the request. */
export type Trust = {
  verdict: Verdict;
  risk_score: number;
  /**
   * False when the score is a fallback rather than a measurement — LayerCall
   * was unreachable, timed out, or the key was out of quota.
   *
   * Branch on THIS before you branch on the verdict for anything punitive. A
   * fallback always reads `allow`, so code that only checks the verdict will
   * silently let everything through during an outage — which is the intended
   * behaviour, but you should be able to tell the difference, and log it.
   */
  scored: boolean;
  top_signals: string[];
  /** Present only when scored is false. */
  error?: string;
  /** The raw API response, when scored. */
  result?: UserResult;
};

export type MiddlewareOptions = {
  apiKey?: string;
  baseUrl?: string;
  /** Per-attempt timeout in ms. Default 2000 — see the note on latency below. */
  timeoutMs?: number;
  strictness?: 0 | 1 | 2 | 3;
  /** Where to read the signup fields from. Defaults read from `req.body`. */
  extract?: (req: Req) => {
    ip?: string;
    email?: string;
    phone?: string;
    domain?: string;
    device_id?: string;
  };
  /**
   * Decide whether a given request is worth a lookup. Default: only
   * POST/PUT/PATCH — see the billing note below.
   */
  shouldScore?: (req: Req) => boolean;
  /** Property name on the request object. Default "trust". */
  property?: string;
  /**
   * Called when the verdict is "block". Return true if you handled the
   * response; the middleware then stops and does NOT call next().
   *
   * There is deliberately no `autoBlock: true`. A one-line install that starts
   * rejecting people is the wrong default for a fraud tool: the failure is
   * silent, it lands on real customers, and the person who installed it finds
   * out from a support ticket. Blocking is a decision about someone's access
   * to your product, so this package makes you write the line that does it.
   */
  onBlock?: (req: Req, res: Res, trust: Trust) => boolean | void;
};

const FALLBACK = (error: string): Trust => ({
  // Fails OPEN, always.
  //
  // If LayerCall is down, slow, or the account is over quota, the customer's
  // signup form must keep working. A fraud check that takes signups offline
  // during an outage has cost more than the fraud it was bought to stop — and
  // unlike fraud, it hits every legitimate user at once.
  verdict: "allow",
  risk_score: 0,
  scored: false,
  top_signals: [],
  error,
});

/**
 * Score a request and attach the verdict as `req.trust`.
 *
 * Mount it on the routes that matter, not globally:
 *
 *   app.post("/signup", layercall(), (req, res) => {
 *     if (req.trust.verdict === "block") return res.status(403).json({ error: "..." });
 *     if (req.trust.verdict === "review") flagForManualReview(req.trust);
 *     createAccount(req.body);
 *   });
 *
 * Mounted globally with app.use() it bills a lookup for every request that
 * passes shouldScore, which is why the default is POST/PUT/PATCH only rather
 * than everything. A global mount on a busy app is the fastest way to spend a
 * month's quota on requests for favicon.ico.
 *
 * Latency: this makes a network call, so it sits in the critical path of the
 * request. The 2s default timeout is a deliberate trade — a signup that takes
 * two extra seconds is bad, and a signup that hangs for ten is worse.
 */
export function layercall(options: MiddlewareOptions = {}) {
  const apiKey = options.apiKey ?? process.env.LAYERCALL_API_KEY;
  if (!apiKey) {
    throw new Error(
      "LayerCall: no API key. Pass { apiKey } or set LAYERCALL_API_KEY. " +
        "Get one free at https://www.layercall.com/get-key",
    );
  }

  const client = new LayerCall({
    apiKey,
    baseUrl: options.baseUrl,
    timeoutMs: options.timeoutMs ?? 2000,
    // No retries in a request path — a retry here is latency the end user
    // waits through. The fallback is a better answer than a slower one.
    retries: 0,
  });

  const prop = options.property ?? "trust";
  const shouldScore =
    options.shouldScore ??
    ((req: Req) => ["POST", "PUT", "PATCH"].includes((req.method ?? "").toUpperCase()));

  return async function layercallMiddleware(req: Req, res: Res, next: Next) {
    try {
      if (!shouldScore(req)) {
        (req as Record<string, unknown>)[prop] = FALLBACK("skipped");
        return next();
      }

      const input: Extracted = options.extract ? options.extract(req) : defaultExtract(req);
      const ip = input.ip ?? callerIp(req);
      if (!ip && !input.email && !input.phone) {
        (req as Record<string, unknown>)[prop] = FALLBACK("nothing to score");
        return next();
      }

      const result = await client.scoreUser({
        ...input,
        ip,
        strictness: options.strictness,
      });

      const trust: Trust = {
        verdict: result.verdict,
        risk_score: result.risk_score,
        scored: true,
        top_signals: result.top_signals ?? [],
        result,
      };
      (req as Record<string, unknown>)[prop] = trust;

      if (trust.verdict === "block" && options.onBlock) {
        if (options.onBlock(req, res, trust) === true) return;
      }
      next();
    } catch (err) {
      // Every failure path lands here and every one of them proceeds.
      (req as Record<string, unknown>)[prop] = FALLBACK(
        err instanceof Error ? err.message : String(err),
      );
      next();
    }
  };
}

type Extracted = {
  ip?: string;
  email?: string;
  phone?: string;
  domain?: string;
  device_id?: string;
};

function defaultExtract(req: Req): Extracted {
  const b = (req.body ?? {}) as Record<string, unknown>;
  const str = (v: unknown) => (typeof v === "string" && v.trim() ? v.trim() : undefined);
  return {
    email: str(b.email) ?? str(b.emailAddress) ?? str(b.email_address),
    phone: str(b.phone) ?? str(b.phoneNumber) ?? str(b.phone_number),
    domain: str(b.domain),
    device_id: str(b.device_id) ?? str(b.deviceId),
  };
}

/**
 * The end user's address, not your load balancer's.
 *
 * Prefers req.ip, which Express derives correctly ONLY when `trust proxy` is
 * configured. Without it Express reports the proxy's address, so behind any
 * CDN or ingress every visitor looks like one IP — and that one IP accrues
 * every signal from every user, which is worse than having no IP at all.
 */
function callerIp(req: Req): string | undefined {
  if (req.ip) return req.ip;
  const xff = req.headers["x-forwarded-for"];
  const raw = Array.isArray(xff) ? xff[0] : xff;
  const first = raw?.split(",")[0]?.trim();
  return first || req.socket?.remoteAddress || undefined;
}

export default layercall;

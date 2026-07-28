import { LayerCall, type UserResult, type Verdict } from "./index.js";

// Next.js helpers — App Router route handlers and server actions.
//
// Deliberately NOT a next.config middleware export. Next.js middleware runs on
// every matched request before routing, so a network call there adds LayerCall's
// latency to page loads that have nothing to do with signups, and bills a
// lookup for each one. Scoring belongs at the point where an account is
// actually created. Nothing stops you calling scoreRequest() from middleware if
// you have a reason to; the default just is not that.

export type Trust = {
  verdict: Verdict;
  risk_score: number;
  /**
   * False when the score is a fallback rather than a measurement — LayerCall
   * was unreachable, timed out, or the key was out of quota.
   *
   * Check this before acting punitively. A fallback always reads `allow`, so
   * code that only inspects the verdict will let everything through during an
   * outage — intended, but you should be able to tell, and log it.
   */
  scored: boolean;
  top_signals: string[];
  error?: string;
  result?: UserResult;
};

export type ScoreOptions = {
  apiKey?: string;
  baseUrl?: string;
  /** Per-attempt timeout in ms. Default 2000. */
  timeoutMs?: number;
  strictness?: 0 | 1 | 2 | 3;
  /** Fields to score. Anything omitted is read from the JSON body. */
  input?: { ip?: string; email?: string; phone?: string; domain?: string; device_id?: string };
};

const FALLBACK = (error: string): Trust => ({
  // Fails OPEN, always. If LayerCall is down or over quota, signups keep
  // working. A fraud check that takes signups offline during an outage costs
  // more than the fraud it was bought to stop, and it hits every legitimate
  // user at once rather than a few bad ones.
  verdict: "allow",
  risk_score: 0,
  scored: false,
  top_signals: [],
  error,
});

/**
 * Score the person behind a request.
 *
 *   export async function POST(req: Request) {
 *     const trust = await scoreRequest(req);
 *     if (trust.verdict === "block") {
 *       return Response.json({ error: "Could not verify" }, { status: 403 });
 *     }
 *     ...
 *   }
 *
 * Reads the JSON body when email/phone are not passed explicitly. The body is
 * cloned first, so the handler can still read it afterwards — consuming it here
 * would leave the caller with an already-used stream and a confusing error far
 * from its cause.
 */
export async function scoreRequest(req: Request, options: ScoreOptions = {}): Promise<Trust> {
  const apiKey = options.apiKey ?? process.env.LAYERCALL_API_KEY;
  if (!apiKey) {
    return FALLBACK("no API key — set LAYERCALL_API_KEY or pass { apiKey }");
  }

  try {
    const given = options.input ?? {};
    let body: Record<string, unknown> = {};
    if (!given.email && !given.phone) {
      try {
        body = (await req.clone().json()) as Record<string, unknown>;
      } catch {
        // Not JSON, or no body. IP alone is still worth scoring.
      }
    }

    const str = (v: unknown) => (typeof v === "string" && v.trim() ? v.trim() : undefined);
    const input = {
      ip: given.ip ?? callerIp(req),
      email: given.email ?? str(body.email) ?? str(body.emailAddress),
      phone: given.phone ?? str(body.phone) ?? str(body.phoneNumber),
      domain: given.domain ?? str(body.domain),
      device_id: given.device_id ?? str(body.device_id) ?? str(body.deviceId),
    };

    if (!input.ip && !input.email && !input.phone) return FALLBACK("nothing to score");

    const client = new LayerCall({
      apiKey,
      baseUrl: options.baseUrl,
      timeoutMs: options.timeoutMs ?? 2000,
      // No retries in a request path — a retry is latency the user waits
      // through, and the fallback is a better answer than a slower one.
      retries: 0,
    });

    const result = await client.scoreUser({ ...input, strictness: options.strictness });
    return {
      verdict: result.verdict,
      risk_score: result.risk_score,
      scored: true,
      top_signals: result.top_signals ?? [],
      result,
    };
  } catch (err) {
    return FALLBACK(err instanceof Error ? err.message : String(err));
  }
}

/**
 * Wrap a route handler so the verdict arrives as a second argument.
 *
 *   export const POST = withTrust(async (req, trust) => {
 *     if (trust.verdict === "block") return new Response(null, { status: 403 });
 *     return Response.json(await createAccount(await req.json()));
 *   });
 *
 * Same rule as everywhere else: it never rejects on your behalf. It hands you
 * the verdict and you decide, because refusing someone an account is a product
 * decision, not a default.
 */
export function withTrust<C>(
  handler: (req: Request, trust: Trust, ctx: C) => Promise<Response> | Response,
  options: ScoreOptions = {},
) {
  return async function (req: Request, ctx: C): Promise<Response> {
    const trust = await scoreRequest(req, options);
    return handler(req, trust, ctx);
  };
}

/**
 * The end user's address as seen by the platform.
 *
 * On Vercel x-forwarded-for is set by the edge and cannot be forged by the
 * client. Behind other proxies, confirm yours overwrites it rather than
 * appending — a client-supplied value that survives means an attacker chooses
 * which IP gets the blame, and yours is a fine choice from their point of view.
 */
function callerIp(req: Request): string | undefined {
  const h = req.headers;
  const xff = h.get("x-forwarded-for");
  if (xff) return xff.split(",")[0]?.trim() || undefined;
  return h.get("x-real-ip") ?? undefined;
}

export default scoreRequest;

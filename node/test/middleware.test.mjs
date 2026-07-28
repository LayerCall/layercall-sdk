// Exercises the middleware against the live API with a test-mode key.
// Mock req/res/next rather than a real Express instance: the middleware is
// (req, res, next) and nothing here needs Express's routing to be honest.
import { layercall } from "../dist/express.js";
import { scoreRequest, withTrust } from "../dist/next.js";

// Same env loading as scripts/tests/contract.test.mjs — the key lives in
// .env.local both locally and in CI, and reading only process.env meant this
// passed on a laptop where it happened to be exported and failed in CI where
// it was not.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

// This file sits at sdk/test/, so the repo root is two levels up. Also try the
// working directory, since the npm script cds into sdk/ and a developer may
// run the file directly from either place.
const here = fileURLToPath(new URL(".", import.meta.url));
for (const p of [
  resolve(here, "../../.env.local"),
  resolve(process.cwd(), ".env.local"),
  resolve(process.cwd(), "../.env.local"),
]) {
  try {
    for (const line of readFileSync(p, "utf8").split("\n")) {
      const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
      if (m && !process.env[m[1]]) process.env[m[1]] = m[2].trim();
    }
    break;
  } catch {
    // Try the next location.
  }
}

const KEY = process.env.LAYERCALL_BENCH_KEY;
if (!KEY) throw new Error("set LAYERCALL_BENCH_KEY (env or .env.local)");
if (!KEY.startsWith("tl_test_")) {
  throw new Error("LAYERCALL_BENCH_KEY must be a tl_test_ key so this never bills.");
}

let pass = 0, fail = 0;
const check = async (name, fn) => {
  try { await fn(); console.log(`  ✓ ${name}`); pass++; }
  catch (e) { console.log(`  ✗ ${name}\n      ${e.message}`); fail++; }
};

/**
 * For assertions that need the live API to actually answer.
 *
 * One retry, and only one. These tests reach a real service over a real
 * network, and the middleware is BUILT to fail open — so a momentary blip
 * produces scored:false and a red test that says nothing about our code. A
 * suite that cries wolf gets ignored, and an ignored suite is worse than none.
 *
 * One retry separates a blip from a break: a genuine wiring fault fails twice.
 * It is deliberately not three — at that point it stops being a test and
 * becomes a way of never hearing bad news.
 */
const checkLive = async (name, fn) => {
  try { await fn(); console.log(`  ✓ ${name}`); pass++; return; }
  catch { /* one blip allowed */ }
  await new Promise((r) => setTimeout(r, 1500));
  try { await fn(); console.log(`  ✓ ${name} (passed on retry)`); pass++; }
  catch (e) { console.log(`  ✗ ${name}\n      ${e.message}`); fail++; }
};
const eq = (a, b, what) => { if (a !== b) throw new Error(`${what}: expected ${b}, got ${a}`); };

const mkReq = (over = {}) => ({
  method: "POST", headers: {}, socket: {}, body: {}, ...over,
});
const run = (mw, req) => new Promise((resolve) => {
  const res = { _sent: null, status(c) { this._sent = c; return this; }, json(b) { this._body = b; return this; } };
  mw(req, res, (err) => resolve({ req, res, err, nexted: true }));
});

console.log("\nEXPRESS");

await checkLive("a clean signup is scored and attached as req.trust", async () => {
  const mw = layercall({ apiKey: KEY });
  const { req } = await run(mw, mkReq({
    body: { email: "hello@gmail.com" },
    headers: { "x-forwarded-for": "8.8.8.8" },
  }));
  eq(typeof req.trust.risk_score, "number", "risk_score type");
  eq(req.trust.scored, true, "scored");
  if (!["allow", "review", "block"].includes(req.trust.verdict)) throw new Error("bad verdict");
});

await checkLive("a disposable email raises the score", async () => {
  const mw = layercall({ apiKey: KEY });
  const { req } = await run(mw, mkReq({
    body: { email: "test@mailinator.com" },
    headers: { "x-forwarded-for": "8.8.8.8" },
  }));
  if (req.trust.risk_score <= 0) throw new Error(`expected a raised score, got ${req.trust.risk_score}`);
  if (!req.trust.top_signals.length) throw new Error("expected top_signals to explain why");
});

await check("FAILS OPEN when the API is unreachable", async () => {
  // The single most important behaviour in this file. If LayerCall is down,
  // the customer's signup must still work.
  const mw = layercall({ apiKey: KEY, baseUrl: "https://127.0.0.1:9", timeoutMs: 700 });
  const { req, nexted } = await run(mw, mkReq({ body: { email: "a@b.com" } }));
  eq(nexted, true, "next() must still be called");
  eq(req.trust.verdict, "allow", "verdict during an outage");
  eq(req.trust.scored, false, "scored must be false so the app can tell");
  if (!req.trust.error) throw new Error("the reason must be surfaced, not swallowed");
});

await check("GET requests are not scored (quota protection)", async () => {
  const mw = layercall({ apiKey: KEY });
  const { req } = await run(mw, mkReq({ method: "GET" }));
  eq(req.trust.scored, false, "scored");
  eq(req.trust.error, "skipped", "reason");
});

await check("onBlock is never invoked on an allow verdict", async () => {
  let called = false;
  const mw = layercall({ apiKey: KEY, onBlock: () => { called = true; } });
  await run(mw, mkReq({ body: { email: "hello@gmail.com" }, headers: { "x-forwarded-for": "8.8.8.8" } }));
  eq(called, false, "onBlock called");
});

await check("a missing key fails loudly at setup, not silently at runtime", async () => {
  const saved = process.env.LAYERCALL_API_KEY;
  delete process.env.LAYERCALL_API_KEY;
  try {
    layercall({});
    throw new Error("expected a throw");
  } catch (e) {
    if (!/API key/i.test(e.message)) throw new Error(`wrong error: ${e.message}`);
  } finally { if (saved) process.env.LAYERCALL_API_KEY = saved; }
});

console.log("\nNEXT.JS");

await checkLive("scoreRequest reads the JSON body", async () => {
  const req = new Request("https://app.example/signup", {
    method: "POST",
    headers: { "content-type": "application/json", "x-forwarded-for": "8.8.8.8" },
    body: JSON.stringify({ email: "test@mailinator.com" }),
  });
  const trust = await scoreRequest(req, { apiKey: KEY });
  eq(trust.scored, true, "scored");
  if (trust.risk_score <= 0) throw new Error("disposable email should raise the score");
});

await check("the handler can still read the body afterwards", async () => {
  // scoreRequest clones; consuming the stream here would hand the caller an
  // already-used body and an error a long way from its cause.
  const req = new Request("https://app.example/signup", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "hello@gmail.com", name: "Ada" }),
  });
  await scoreRequest(req, { apiKey: KEY });
  const body = await req.json();
  eq(body.name, "Ada", "body still readable");
});

await checkLive("withTrust passes the verdict through to the handler", async () => {
  const POST = withTrust(async (_req, trust) => Response.json({ v: trust.verdict, scored: trust.scored }), { apiKey: KEY });
  const res = await POST(new Request("https://app.example/s", {
    method: "POST",
    headers: { "content-type": "application/json", "x-forwarded-for": "8.8.8.8" },
    body: JSON.stringify({ email: "hello@gmail.com" }),
  }), {});
  const body = await res.json();
  if (!["allow", "review", "block"].includes(body.v)) throw new Error(`bad verdict: ${body.v}`);
  // Assert it was MEASURED, not a fallback. Without this the test passes
  // during a total outage, because a fallback verdict is "allow" and "allow"
  // is in the list above — a green test that proves only that the fallback
  // works, which is a different test and already exists below.
  eq(body.scored, true, "must be a real score, not a fallback");
});

await check("scoreRequest FAILS OPEN too", async () => {
  const trust = await scoreRequest(
    new Request("https://app.example/s", { method: "POST", body: "{}" }),
    { apiKey: KEY, baseUrl: "https://127.0.0.1:9", timeoutMs: 700 },
  );
  eq(trust.verdict, "allow", "verdict");
  eq(trust.scored, false, "scored");
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);

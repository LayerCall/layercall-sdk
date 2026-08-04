// Does the SDK still describe the API truthfully?
//
// The SDKs have zero dependencies, so nothing can rot underneath them — no
// supply chain, no transitive CVEs, no dependabot churn. That removes most of
// what usually breaks a client library and leaves exactly one real risk: OUR
// OWN API moves and the SDK does not follow.
//
// That failure is silent in both directions and neither is caught by anything
// else we run:
//
//   API adds a field, SDK does not declare it
//     -> TypeScript users cannot reach it without a cast. The feature ships
//        and the people we built the SDK for cannot use it. Found exactly this
//        on the first run: /v1/score/ip returns `cached`, IpResult never
//        mentioned it.
//
//   SDK declares a field the API no longer returns
//     -> the types promise something that arrives as undefined at runtime,
//        which is worse than an error because it fails silently in production.
//
// Runs against the live deployment with a tl_test_ key.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
const require0 = createRequire(import.meta.url);
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = fileURLToPath(new URL(".", import.meta.url));
for (const p of [resolve(here, "../../.env.local"), resolve(process.cwd(), ".env.local")]) {
  try {
    for (const line of readFileSync(p, "utf8").split("\n")) {
      const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
      if (m && !process.env[m[1]]) process.env[m[1]] = m[2].trim();
    }
    break;
  } catch { /* next */ }
}

const KEY = process.env.LAYERCALL_BENCH_KEY;
if (!KEY) throw new Error("set LAYERCALL_BENCH_KEY (env or .env.local)");
if (!KEY.startsWith("tl_test_")) throw new Error("must be a tl_test_ key so this never bills");
const BASE = process.env.SDK_CONTRACT_BASE ?? "https://www.layercall.com";

const SRC = readFileSync(resolve(here, "../src/index.ts"), "utf8");

/** Top-level field names declared on an exported SDK type.
 *
 * Handles intersections (`= Foo & {`) as well as plain object types, and
 * follows the intersected names so fields declared on a shared type still
 * count as declared. Without that, factoring three repeated optional fields
 * into TestModeMarkers read to this test as five types losing every field —
 * a red build for a refactor that changed nothing a consumer can see.
 */
// Fields declared with `?:` are legitimately absent from most responses —
// hijacked_source only appears when the signal fires, agent only when you pass
// one. Flagging those as "the type promises undefined" made it impossible for a
// correctly-optional field to ever pass, so optionality is now part of what
// gets parsed rather than being flattened away.
//
// The limit is worth naming: this cannot distinguish "optional and sometimes
// present" from "declared and never returned by anything". OPTIONAL_PROBES
// below covers that for the ones we know how to trigger.
function optionalFields(typeName) {
  const m = SRC.match(new RegExp(`export type ${typeName} = ([^{]*)\\{(.*?)\\n\\};`, "s"));
  if (!m) return new Set();
  return new Set([...m[2].matchAll(/^ {2}(\w+)\?:/gm)].map((x) => x[1]));
}

function declaredFields(typeName, seen = new Set()) {
  if (seen.has(typeName)) return [];
  seen.add(typeName);
  const m = SRC.match(new RegExp(`export type ${typeName} = ([^{]*)\\{(.*?)\\n\\};`, "s"));
  if (!m) throw new Error(`could not find "export type ${typeName}" in src/index.ts`);
  const inherited = [...m[1].matchAll(/(\w+)\s*&/g)].flatMap((x) => declaredFields(x[1], seen));
  const fields = [...inherited, ...[...m[2].matchAll(/^ {2}(\w+)\??:/gm)].map((x) => x[1])];
  // Guard against a regex that silently matches nothing — the same failure
  // that once published "0 verified ASNs" because Object.values() on a Set
  // returns []. An empty parse must be an error, not a passing test.
  if (fields.length < 3) throw new Error(`${typeName}: parsed only ${fields.length} fields — the regex has drifted`);
  return fields;
}

let pass = 0, fail = 0;
const eq = (a, b, what) => { if (a !== b) throw new Error(`${what}: expected ${b}, got ${a}`); };

async function check(name, fn) {
  try { await fn(); console.log(`  ✓ ${name}`); pass++; }
  catch (e) { console.log(`  ✗ ${name}\n      ${e.message}`); fail++; }
}

async function api(path) {
  const res = await fetch(BASE + path, { headers: { "X-Api-Key": KEY } });
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return res.json();
}

// Ignored because they are documented as varying per request rather than being
// part of the response's shape.
const IGNORE = new Set(["error"]);

async function compare(typeName, path) {
  const declared = new Set(declaredFields(typeName));
  const actual = new Set(Object.keys(await api(path)).filter((k) => !IGNORE.has(k)));

  const optional = optionalFields(typeName);
  const missingFromSdk = [...actual].filter((k) => !declared.has(k));
  const notInApi = [...declared].filter((k) => !actual.has(k) && !optional.has(k));

  const problems = [];
  if (missingFromSdk.length) {
    problems.push(`API returns ${missingFromSdk.map((f) => `"${f}"`).join(", ")} but ${typeName} does not declare it — TypeScript users cannot reach it`);
  }
  if (notInApi.length) {
    problems.push(`${typeName} declares ${notInApi.map((f) => `"${f}"`).join(", ")} but the API does not return it — the type promises undefined`);
  }
  if (problems.length) throw new Error(problems.join("\n      "));
}

console.log("\nSDK TYPES vs LIVE API\n");
await check("IpResult matches /v1/score/ip", () => compare("IpResult", "/v1/score/ip?ip=8.8.8.8"));
await check("EmailResult matches /v1/verify/email", () => compare("EmailResult", "/v1/verify/email?email=hello@gmail.com"));
await check("PhoneResult matches /v1/lookup/phone", () => compare("PhoneResult", "/v1/lookup/phone?phone=%2B14155552671"));
await check("DomainResult matches /v1/score/domain", () => compare("DomainResult", "/v1/score/domain?domain=example.com"));
await check("UserResult matches /v1/score/user", () => compare("UserResult", "/v1/score/user?ip=8.8.8.8&email=hello@gmail.com"));

console.log("\nAPI SURFACE vs SDK COVERAGE\n");

await check("every public endpoint has an SDK method", () => {
  // The parity check below compares the two SDKs to EACH OTHER, so an endpoint
  // missing from both passed silently — which is how /v1/score/device,
  // /v1/report and /v1/verify/agent all shipped with no client at all. This
  // compares them to the API instead.
  const { readdirSync } = require0("node:fs");
  const walk = (dir, out = []) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = `${dir}/${e.name}`;
      if (e.isDirectory()) walk(p, out);
      else if (e.name === "route.ts") out.push(p);
    }
    return out;
  };
  const v1 = resolve(here, "../../app/v1");
  const endpoints = new Set();
  for (const f of walk(v1)) {
    const src = readFileSync(f, "utf8");
    for (const m of src.matchAll(/apiHandler\("([^"]+)"/g)) endpoints.add(m[1]);
    // Routes that build their own handler still expose a path.
    const rel = "/" + f.slice(f.indexOf("app/v1") + 4).replace(/\/route\.ts$/, "");
    if (/export (async function|const) (GET|POST)/.test(src) && !rel.includes("[")) endpoints.add(rel);
  }
  // Management endpoints are configuration, not scoring — the dashboard owns
  // them and an SDK method would be noise.
  const EXEMPT = new Set(["/v1/rules", "/v1/rules/import"]);
  const covered = {
    "/v1/score/ip": "scoreIp", "/v1/verify/email": "verifyEmail",
    "/v1/lookup/phone": "lookupPhone", "/v1/score/domain": "scoreDomain",
    "/v1/score/user": "scoreUser", "/v1/score/device": "scoreDevice",
    "/v1/verify/agent": "verifyAgent", "/v1/report": "report", "/v1/batch": "batch",
    "/v1/agent/authorize": "authorizeAgent", "/v1/agent/policy": "getAgentPolicy",
    "/v1/outcome": "reportOutcome",
  };
  const missing = [];
  for (const ep of endpoints) {
    if (EXEMPT.has(ep)) continue;
    const method = covered[ep];
    if (!method) { missing.push(`${ep} (no SDK method mapped)`); continue; }
    if (!new RegExp(`^ {2}${method}[<(]`, "m").test(SRC)) missing.push(`${ep} -> ${method}() absent from the Node SDK`);
  }
  if (missing.length) throw new Error(missing.join("; "));
});

console.log("\nNODE vs PYTHON PARITY\n");
await check("both SDKs expose the same methods", () => {
  const py = readFileSync(resolve(here, "../../sdk-python/layercall/__init__.py"), "utf8");
  // EVERY public method on the class, not an allow-list of prefixes.
  //
  // This used to match /^ {2}(score[A-Z]\w*|verify\w*|lookup\w*|batch|report)[<(]/,
  // which enumerated the naming conventions that existed when it was written.
  // authorizeAgent, getAgentPolicy, setAgentPolicy and reportOutcome all fell
  // outside it, so the check reported parity while Python was missing four
  // methods — a developer choosing Python would have got a strictly smaller
  // product and nothing would have said so.
  //
  // Same shape of failure as the test-mode endpoint enumeration: an instrument
  // that lists what it knows about goes blind exactly when something new is
  // added, which is the only time it matters.
  const nodeMethods = [...SRC.matchAll(/^ {2}([a-z]\w*)\(/gm)]
    .map((m) => m[1])
    .filter((m) => m !== "constructor" && !m.startsWith("_"));
  const toSnake = (s) => s.replace(/[A-Z]/g, (c) => "_" + c.toLowerCase());
  const pyMethods = new Set([...py.matchAll(/^ {4}def (\w+)\(/gm)].map((m) => m[1]).filter((m) => !m.startsWith("_")));
  if (nodeMethods.length < 4) throw new Error(`parsed only ${nodeMethods.length} Node methods — the regex has drifted`);
  const missing = nodeMethods.map(toSnake).filter((m) => !pyMethods.has(m));
  if (missing.length) {
    throw new Error(`Python is missing: ${missing.join(", ")} — a developer choosing Python gets less product than one choosing Node`);
  }
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);

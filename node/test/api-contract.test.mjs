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

/** Top-level field names declared on an exported SDK type. */
function declaredFields(typeName) {
  const m = SRC.match(new RegExp(`export type ${typeName} = \\{(.*?)\\n\\};`, "s"));
  if (!m) throw new Error(`could not find "export type ${typeName}" in src/index.ts`);
  const fields = [...m[1].matchAll(/^ {2}(\w+)\??:/gm)].map((x) => x[1]);
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

  const missingFromSdk = [...actual].filter((k) => !declared.has(k));
  const notInApi = [...declared].filter((k) => !actual.has(k));

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

console.log("\nNODE vs PYTHON PARITY\n");
await check("both SDKs expose the same methods", () => {
  const py = readFileSync(resolve(here, "../../sdk-python/layercall/__init__.py"), "utf8");
  // Node: methods on the LayerCall class. Python: public defs, snake_cased.
  const nodeMethods = [...SRC.matchAll(/^ {2}(score[A-Z]\w*|verify\w*|lookup\w*|batch)\(/gm)].map((m) => m[1]);
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

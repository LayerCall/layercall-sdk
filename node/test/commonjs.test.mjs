// require("layercall") must work.
//
// 1.2.9 and earlier declared only an "import" condition, so in a CommonJS
// project — still most Express apps — require("layercall") threw
// ERR_PACKAGE_PATH_NOT_EXPORTED before a line of ours ran, and TypeScript in
// the same project refused the import with TS1479. The README never said the
// package was ESM-only, so the first thing a new user tried was the one thing
// that could not work.
//
// These resolve the package BY NAME, which Node allows from inside a package
// with an exports map, so they go through the same "exports" lookup a
// customer's require does — not through a relative path into dist/ that would
// pass no matter what the manifest said.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const root = resolve(fileURLToPath(new URL(".", import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8"));

let pass = 0;
const fails = [];
const check = (label, cond, why) => {
  if (cond) {
    pass++;
    console.log(`  ok   ${label}`);
  } else {
    fails.push(`${label}${why ? ` — ${why}` : ""}`);
    console.log(`  FAIL ${label}`);
  }
};

console.log("require(\"layercall\") works");

for (const [sub, names] of [
  ["layercall", ["LayerCall", "LayerCallError"]],
  ["layercall/express", ["layercall"]],
  ["layercall/next", ["scoreRequest", "withTrust"]],
]) {
  let cjs = null;
  let err = null;
  try {
    cjs = require(sub);
  } catch (e) {
    err = e;
  }
  check(`require("${sub}") loads`, cjs !== null, err && `${err.code ?? ""} ${err.message.split("\n")[0]}`);
  if (!cjs) continue;
  for (const n of names) check(`require("${sub}").${n} is a function`, typeof cjs[n] === "function");

  // Same source, two builds: the CommonJS one must not quietly export less.
  const esm = await import(sub);
  const missing = Object.keys(esm).filter((k) => k !== "default" && !(k in cjs));
  check(`require("${sub}") exports everything import("${sub}") does`, missing.length === 0,
    `missing from the CommonJS build: ${missing.join(", ")}`);
}

// Every entry point, including one added later, must answer both ways.
for (const [path, target] of Object.entries(pkg.exports ?? {})) {
  const conds = typeof target === "object" && target !== null ? Object.keys(target) : [];
  check(`exports["${path}"] has both "import" and "require"`,
    conds.includes("import") && conds.includes("require"),
    `conditions: ${conds.join(", ") || "(a bare string)"}`);
}

// Inside a "type": "module" package, .js means ESM unless a nearer
// package.json says otherwise. Without this file Node parses the CommonJS
// build as ESM and fails on `exports`.
let marker = null;
try {
  marker = JSON.parse(readFileSync(resolve(root, "dist/cjs/package.json"), "utf8"));
} catch {}
check("dist/cjs is marked CommonJS", marker?.type === "commonjs");

if (fails.length) {
  console.error(`✗ ${fails.length} failure(s):`);
  for (const f of fails) console.error(`  - ${f}`);
  process.exit(1);
}
console.log(`✓ commonjs — ${pass} checks`);

// The published types say what a field is, not how we found out.
//
// A doc comment on an exported type is what a customer's editor shows on
// hover. 1.2.9 shipped our own audit history there — "Measured against the
// live API on 10 September 2026", "the one thing the marketing points at was a
// compile error", a path into the private API code — in the tooltip of the
// type every response carries. That history stays in the source as plain
// comments, which TypeScript does not copy into a .d.ts.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL(".", import.meta.url)), "..");
const FILES = ["dist/index.d.ts", "dist/cjs/index.d.ts", "dist/express.d.ts", "dist/next.d.ts"];
const MONTH = "January|February|March|April|May|June|July|August|September|October|November|December";
const MARKERS = [
  [/\b20\d\d-\d\d-\d\d\b/, "a date"],
  [new RegExp(`\\b(${MONTH}) 20\\d\\d\\b|\\b\\d{1,2} (${MONTH})\\b`), "a date"],
  [/\bMeasured\b/, "a measurement note"],
  [/\bmarketing\b|\bcompetitor/i, "a note about our marketing"],
  [/route\.ts|app\/v1\/|lib\/[a-z]+\.ts/, "a path into the private API code"],
  [/\baudit\b/i, "an audit note"],
];

let checked = 0;
const found = [];
for (const f of FILES) {
  const src = readFileSync(resolve(root, f), "utf8");
  for (const m of src.matchAll(/\/\*\*[\s\S]*?\*\//g)) {
    checked++;
    for (const [re, what] of MARKERS) {
      const hit = m[0].match(re);
      if (hit) {
        const line = src.slice(0, m.index).split("\n").length;
        found.push(`${f}:${line} — ${what}: "${hit[0]}"`);
      }
    }
  }
}

console.log("The published types say what a field is");
if (checked < 50) {
  console.error(`✗ only ${checked} doc comments found — is dist built?`);
  process.exit(1);
}
if (found.length) {
  console.error(`✗ ${found.length} internal note(s) in customer-facing doc comments:`);
  for (const f of found) console.error(`  - ${f}`);
  process.exit(1);
}
console.log(`✓ published-types — ${checked} doc comments, none carrying our history`);

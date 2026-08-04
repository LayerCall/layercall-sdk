#!/usr/bin/env node
/**
 * npx layercall — check a value from the terminal, no install.
 *
 * This exists as a discovery surface as much as a tool. `npx layercall ip
 * 8.8.8.8` is a smaller ask than reading docs and writing a fetch call, and a
 * developer who runs it once has already seen the response shape.
 */
import { LayerCall, LayerCallError } from "./index.js";

const C = {
  red: "\x1b[31m", green: "\x1b[32m", yellow: "\x1b[33m",
  dim: "\x1b[2m", bold: "\x1b[1m", off: "\x1b[0m",
};

const USAGE = `${C.bold}layercall${C.off} — trust and fraud signals from the terminal

  ${C.dim}npx layercall${C.off} ip      8.8.8.8
  ${C.dim}npx layercall${C.off} email   someone@example.com
  ${C.dim}npx layercall${C.off} phone   +14155552671 [--country US]
  ${C.dim}npx layercall${C.off} domain  example.com
  ${C.dim}npx layercall${C.off} user    --ip 1.2.3.4 --email a@b.com [--phone +1...]
  ${C.dim}npx layercall${C.off} device  <fingerprint from /fp.js>
  ${C.dim}npx layercall${C.off} report  ip 1.2.3.4 [--reason "carding"]
  ${C.dim}npx layercall${C.off} agent   https://yoursite.com/signup --header "signature-agent: ..."
  ${C.dim}npx layercall${C.off} outcome req_abc123 fraud

Options
  --strictness 0..3   0 lenient, 1 balanced (default), 3 paranoid
  --json              print the raw response

Set LAYERCALL_API_KEY in your environment.
Free key, 1,000 lookups a month: https://www.layercall.com/get-key
`;

const argv = process.argv.slice(2);
if (argv.length === 0 || argv[0] === "-h" || argv[0] === "--help") {
  console.log(USAGE);
  process.exit(0);
}

const flags: Record<string, string> = {};
const positional: string[] = [];
// Collected separately: a signed request carries three or four headers, and the
// generic parser above keeps only the last value for a repeated key.
const headerFlags: Record<string, string> = {};
for (let i = 0; i < argv.length; i++) {
  if (argv[i].startsWith("--")) {
    const key = argv[i].slice(2);
    const next = argv[i + 1];
    const val = next && !next.startsWith("--") ? (i++, next) : "true";
    if (key === "header") {
      const at = val.indexOf(":");
      if (at > 0) headerFlags[val.slice(0, at).trim().toLowerCase()] = val.slice(at + 1).trim();
    } else flags[key] = val;
  } else positional.push(argv[i]);
}

const key = process.env.LAYERCALL_API_KEY;
if (!key) {
  console.error(
    `${C.red}LAYERCALL_API_KEY is not set.${C.off}\n\n` +
      `  export LAYERCALL_API_KEY=tl_live_...\n\n` +
      `Get a free key (1,000 lookups a month, no card):\n  https://www.layercall.com/get-key`,
  );
  process.exit(1);
}

const strictness = flags.strictness ? (Number(flags.strictness) as 0 | 1 | 2 | 3) : undefined;
const lc = new LayerCall({ apiKey: key });
const [cmd, value] = positional;

// Signals where `true` is REASSURING, not alarming. Rendering these amber was
// the same polarity bug that once showed "resolves: yes" as a warning on the
// web tools — a caller reads colour before text, so getting it wrong actively
// misinforms.
const GOOD_WHEN_TRUE = new Set([
  "resolves",
  "mx_found",
  "has_spf",
  "has_dmarc",
  "syntax_valid",
  "is_possible",
  "assigned_area_code",
  "is_fictional",
]);

function verdictColour(v: string) {
  return v === "block" ? C.red : v === "review" ? C.yellow : C.green;
}

function render(r: Record<string, unknown>) {
  if (flags.json) {
    console.log(JSON.stringify(r, null, 2));
    return;
  }
  // Say it before the score, not after.
  //
  // A test key renders a fabricated verdict exactly as convincingly as a real
  // one — same colours, same layout, same confidence. Someone trying us for
  // the first time with tl_test_ would read invented numbers as our accuracy
  // and leave. The banner has to sit above the thing it is qualifying.
  if (r.test_mode === true) {
    console.log(
      `\n  ${C.yellow}${C.bold}TEST MODE${C.off}${C.dim} — synthetic data. ` +
        `Scores below are fabricated, not real intelligence.${C.off}\n` +
        `  ${C.dim}Use a live key (tl_live_…) to score real values. ` +
        `https://www.layercall.com/docs/test-mode${C.off}`,
    );
  }

  const verdict = String(r.verdict ?? "");
  console.log(
    `\n  ${C.bold}${r.risk_score}${C.off}${C.dim}/100${C.off}  ` +
      `${verdictColour(verdict)}${C.bold}${verdict.toUpperCase()}${C.off}\n`,
  );
  const signals = (r.signals ?? {}) as Record<string, unknown>;
  for (const [k, v] of Object.entries(signals)) {
    if (v === true) {
      const good = GOOD_WHEN_TRUE.has(k);
      console.log(`  ${good ? C.green : C.yellow}${good ? "\u2713" : "\u00b7"}${C.off} ${k}`);
    } else if (v === false && GOOD_WHEN_TRUE.has(k)) {
      // A missing SPF record is worth seeing; a missing risk signal is not.
      console.log(`  ${C.yellow}\u00b7${C.off} ${k}${C.dim} = false${C.off}`);
    } else if (v === null) {
      console.log(`  ${C.dim}? ${k} (unknown, not "no")${C.off}`);
    }
  }
  for (const s of (r.top_signals as string[] | undefined) ?? []) {
    console.log(`  ${C.yellow}·${C.off} ${s}`);
  }
  const geo = r.geo as Record<string, unknown> | undefined;
  if (geo?.country) {
    console.log(`\n  ${C.dim}${[geo.city, geo.country, geo.isp].filter(Boolean).join(" · ")}${C.off}`);
  }
  if (r.vpn_provider) console.log(`  ${C.dim}VPN provider: ${r.vpn_provider}${C.off}`);
  console.log();
}

try {
  let out: Record<string, unknown>;
  switch (cmd) {
    case "ip":
      if (!value) throw new Error("Usage: layercall ip <address>");
      out = (await lc.scoreIp(value, { strictness })) as unknown as Record<string, unknown>;
      break;
    case "email":
      if (!value) throw new Error("Usage: layercall email <address>");
      out = (await lc.verifyEmail(value, { strictness })) as unknown as Record<string, unknown>;
      break;
    case "phone":
      if (!value) throw new Error("Usage: layercall phone <number>");
      out = (await lc.lookupPhone(value, { country: flags.country, strictness })) as unknown as Record<string, unknown>;
      break;
    case "domain":
      if (!value) throw new Error("Usage: layercall domain <domain>");
      out = (await lc.scoreDomain(value)) as unknown as Record<string, unknown>;
      break;
    case "device":
      if (!value) throw new Error("Usage: layercall device <device_id from /fp.js>");
      out = (await lc.scoreDevice({ device_id: value, ip: flags.ip })) as unknown as Record<string, unknown>;
      break;
    case "agent": {
      // Should this agent be allowed to do this, here? Pass the request the
      // agent made to YOU — the signature covers its method, URL and headers,
      // so none of it can be inferred from this side.
      if (!value) throw new Error('Usage: layercall agent <url> [--method POST] [--header "signature-agent: ..."]');
      out = (await lc.authorizeAgent({
        method: flags.method ?? "GET",
        url: value,
        headers: headerFlags,
      })) as unknown as Record<string, unknown>;
      break;
    }
    case "outcome": {
      // Free, and the only thing that improves the engine. Quote the
      // request_id from the score you are reporting on.
      const outcome = positional[2];
      if (!value || (outcome !== "fraud" && outcome !== "legitimate")) {
        throw new Error("Usage: layercall outcome <request_id> <fraud|legitimate>");
      }
      out = (await lc.reportOutcome({ request_id: value, outcome })) as unknown as Record<string, unknown>;
      break;
    }
    case "report": {
      // `layercall report ip 1.2.3.4` — kind first, then the value, because
      // the kind cannot be inferred reliably (a bare string could be a device
      // id or a domain) and guessing wrong writes to the shared network.
      const kind = value;
      const target = positional[2];
      if (!kind || !target) throw new Error("Usage: layercall report <ip|email|phone|domain|device> <value> [--reason ...]");
      out = (await lc.report(kind as never, target, flags.reason)) as unknown as Record<string, unknown>;
      break;
    }
    case "user":
      out = (await lc.scoreUser({
        ip: flags.ip, email: flags.email, phone: flags.phone,
        phone_country: flags.country, strictness,
      })) as unknown as Record<string, unknown>;
      break;
    default:
      console.error(`Unknown command: ${cmd ?? "(none)"}\n`);
      console.log(USAGE);
      process.exit(1);
  }
  render(out);
} catch (err) {
  if (err instanceof LayerCallError) {
    console.error(`\n  ${C.red}${err.message}${C.off}`);
    if (err.isQuota) console.error(`  ${C.dim}Raise your spend cap or upgrade at https://www.layercall.com/dashboard${C.off}`);
    if (err.isAuth) console.error(`  ${C.dim}Check LAYERCALL_API_KEY — it may be revoked.${C.off}`);
    if (err.requestId) console.error(`  ${C.dim}request_id: ${err.requestId}${C.off}`);
    process.exit(1);
  }
  console.error(`\n  ${C.red}${err instanceof Error ? err.message : String(err)}${C.off}\n`);
  process.exit(1);
}

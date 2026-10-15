#!/usr/bin/env node
// 4.19  Check SPF, DKIM and DMARC for the sending domain.
//
//   node scripts/check-mail-dns.mjs notify.baritobahalap.com --dkim-selector resend --root baritobahalap.com
//
// <domain>          the domain in MAIL_FROM (the one you verified in Resend)
// --dkim-selector   selector shown in your mail provider's DNS records (Resend: "resend")
// --root            organisational domain, where DMARC usually lives (defaults to the last 2 labels)
// --spf-include     substring the SPF record must contain (default: "amazonses.com", which Resend uses)
import { resolve4, resolveTxt } from "node:dns/promises";

const args = process.argv.slice(2);
const flag = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : fallback;
};
const domain = args.find(
  (a, i) => !a.startsWith("--") && !args[i - 1]?.startsWith("--"),
);
if (!domain) {
  console.error(
    "usage: check-mail-dns.mjs <sending-domain> [--dkim-selector resend] [--root example.com] [--spf-include amazonses.com]",
  );
  process.exit(2);
}
const selector = flag("dkim-selector", "resend");
const root = flag("root", domain.split(".").slice(-2).join("."));
const spfInclude = flag("spf-include", "amazonses.com");

// A missing record and a broken resolver look the same to a naive script. Prove DNS works first,
// so "FAIL: no record" always means the record is really absent.
try {
  await resolve4("cloudflare.com");
} catch {
  console.error(
    "Cannot resolve DNS from this machine (offline, VPN or sandbox?). Nothing was checked.",
  );
  process.exit(2);
}

const txt = async (name) => {
  try {
    return (await resolveTxt(name)).map((chunks) => chunks.join(""));
  } catch (error) {
    if (error.code === "ENODATA" || error.code === "ENOTFOUND") return [];
    console.error(`DNS error for ${name}: ${error.code}`);
    process.exit(2);
  }
};

let failures = 0;
const report = (level, label, detail = "") => {
  console.log(
    `${level.padEnd(5)} ${label}${detail ? `\n       ${detail}` : ""}`,
  );
  if (level === "FAIL") failures += 1;
};

// ---- SPF: look on the sending domain (the envelope-from domain Resend uses is a "send." subdomain)
const spfCandidates = [domain, `send.${domain}`];
let spf;
for (const name of spfCandidates) {
  const found = (await txt(name)).filter((r) =>
    r.toLowerCase().startsWith("v=spf1"),
  );
  if (found.length > 1)
    report(
      "FAIL",
      `SPF: ${name} has ${found.length} SPF records (must be exactly one)`,
      found.join(" | "),
    );
  if (found.length >= 1) {
    spf = { name, record: found[0] };
    break;
  }
}
if (!spf) {
  report(
    "FAIL",
    `SPF: no v=spf1 record on ${spfCandidates.join(" or ")}`,
    "Add the SPF TXT record from your mail provider's domain page.",
  );
} else if (!spf.record.toLowerCase().includes(spfInclude.toLowerCase())) {
  report(
    "WARN",
    `SPF on ${spf.name} does not mention "${spfInclude}"`,
    spf.record,
  );
} else {
  report("PASS", `SPF on ${spf.name}`, spf.record);
  if (/\+all\b|\s\?all\b/.test(spf.record))
    report("FAIL", "SPF ends in +all/?all (anyone may send as you)");
}

// ---- DKIM
const dkimName = `${selector}._domainkey.${domain}`;
const dkim = (await txt(dkimName)).find((r) => /v=DKIM1|p=/i.test(r));
dkim
  ? report(
      "PASS",
      `DKIM selector "${selector}" at ${dkimName}`,
      `${dkim.slice(0, 60)}…`,
    )
  : report(
      "FAIL",
      `DKIM: no key at ${dkimName}`,
      "Copy the DKIM record from the provider, or pass the right --dkim-selector.",
    );

// ---- DMARC: sending domain first, then organisational domain
let dmarc;
for (const name of [`_dmarc.${domain}`, `_dmarc.${root}`]) {
  const found = (await txt(name)).find((r) =>
    r.toUpperCase().startsWith("V=DMARC1"),
  );
  if (found) {
    dmarc = { name, record: found };
    break;
  }
}
if (!dmarc) {
  report(
    "FAIL",
    `DMARC: no record at _dmarc.${domain} or _dmarc.${root}`,
    `Start with: v=DMARC1; p=none; rua=mailto:dmarc@${root}; adkim=r; aspf=r`,
  );
} else {
  const policy = /(?:^|;)\s*p=(\w+)/i.exec(dmarc.record)?.[1]?.toLowerCase();
  const rua = /rua=/i.test(dmarc.record);
  report("PASS", `DMARC at ${dmarc.name}`, dmarc.record);
  if (policy === "none")
    report(
      "WARN",
      "DMARC policy is p=none (monitoring only)",
      "Fine while you collect reports. Move to p=quarantine once reports are clean for ~2 weeks.",
    );
  if (!rua)
    report(
      "WARN",
      "DMARC has no rua= address, so you will receive no aggregate reports",
    );
}

console.log(
  failures === 0
    ? "\nMail DNS looks sound."
    : `\n${failures} problem(s) to fix before sending.`,
);
process.exit(failures === 0 ? 0 : 1);

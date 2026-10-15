// Server-side sanitisation. Runs BEFORE validation so length limits apply to the
// cleaned value. Output encoding (HTML escaping for email) happens in templates.ts.

// C0/C1 controls except \t \n \r
const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;
// zero-width, bidi overrides/isolates, BOM. Kept: ZWNJ/ZWJ (U+200C/D) used by real scripts and emoji.
const INVISIBLE = /[​‎‏‪-‮⁠-⁤⁦-⁩﻿]/g;

export function sanitizeLine(input: string): string {
  return input
    .normalize("NFC")
    .replace(CONTROL, "")
    .replace(INVISIBLE, "")
    .replace(/\s+/g, " ")
    .trim();
}

export function sanitizeMultiline(input: string): string {
  return input
    .normalize("NFC")
    .replace(/\r\n?/g, "\n")
    .replace(CONTROL, "")
    .replace(INVISIBLE, "")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

export function truncate(input: string, max: number): string {
  return input.length > max ? input.slice(0, max) : input;
}

/**
 * Accepts "0812-3456-7890", "+62 812 3456 7890", "62812...", "0062812...".
 * Returns E.164-ish "+62812..."; anything else is returned stripped so the
 * validator can reject it.
 */
export function normalizeWhatsapp(input: string): string {
  const stripped = input.replace(/[\s().-]/g, "");
  if (stripped.startsWith("+")) return stripped;
  if (stripped.startsWith("00")) return `+${stripped.slice(2)}`;
  if (stripped.startsWith("0")) return `+62${stripped.slice(1)}`;
  if (stripped.startsWith("62")) return `+${stripped}`;
  return stripped;
}

/** Keep origin + path only: query strings and fragments can carry tokens or PII. */
export function cleanReferrer(input: string): string | undefined {
  try {
    const url = new URL(input);
    if (url.protocol !== "https:" && url.protocol !== "http:") return undefined;
    return truncate(`${url.origin}${url.pathname}`, 500);
  } catch {
    return undefined;
  }
}

import { z } from "zod";
import {
  cleanReferrer,
  normalizeWhatsapp,
  sanitizeLine,
  sanitizeMultiline,
  truncate,
} from "./sanitize";

export const DIVISIONS = ["bbt", "bbm", "partnership", "general"] as const;
export const ORG_TYPES = [
  "government",
  "bumn_bumd",
  "corporate",
  "public_figure",
  "association",
  "individual",
] as const;
export const LOCALES = ["id", "en"] as const;

export type Division = (typeof DIVISIONS)[number];
export type OrgType = (typeof ORG_TYPES)[number];
export type Locale = (typeof LOCALES)[number];

// Deliberately conservative: no quotes, commas, colons, brackets or whitespace,
// so the address is safe to drop into a Reply-To header.
const EMAIL_RE =
  /^[^\s@<>"',;:()[\]\\]+@[^\s@<>"',;:()[\]\\]+\.[^\s@<>"',;:()[\]\\]{2,}$/;
const WHATSAPP_RE = /^\+[1-9][0-9]{7,14}$/;
const CODE_RE = /^[a-z0-9_]{1,40}$/;

/** Codes the client turns into localised messages. */
export type ErrorCode =
  | "required"
  | "too_short"
  | "too_long"
  | "invalid"
  | "invalid_email"
  | "invalid_whatsapp"
  | "invalid_division"
  | "invalid_org_type"
  | "invalid_locale"
  | "too_many_links"
  | "consent_required"
  | "captcha_required"
  | "unexpected_field";

const line = (min: number, max: number) =>
  z
    .string()
    .transform(sanitizeLine)
    .pipe(
      z.string().min(1, "required").min(min, "too_short").max(max, "too_long"),
    );

const optionalLine = (max: number) =>
  z
    .string()
    .optional()
    .transform((v) => (v == null ? undefined : sanitizeLine(v) || undefined))
    .pipe(z.string().max(max, "too_long").optional());

const optionalCode = () =>
  z
    .string()
    .optional()
    .transform((v) =>
      v == null ? undefined : v.trim().toLowerCase() || undefined,
    )
    .pipe(z.string().regex(CODE_RE, "invalid").optional());

/** Tracking fields never block a lead: clean, truncate, drop if unusable. */
const lenientTracking = (max: number) =>
  z
    .unknown()
    .transform((v) =>
      typeof v === "string"
        ? truncate(sanitizeLine(v), max) || undefined
        : undefined,
    );

export const inquirySchema = z.strictObject({
  division: z.enum(DIVISIONS, { error: "invalid_division" }),
  locale: z.enum(LOCALES, { error: "invalid_locale" }),

  name: line(2, 120),
  org_type: z.enum(ORG_TYPES, { error: "invalid_org_type" }),
  organization: optionalLine(160),

  email: z
    .string()
    .transform((v) => sanitizeLine(v).toLowerCase())
    .pipe(
      z
        .string()
        .min(1, "required")
        .max(254, "too_long")
        .regex(EMAIL_RE, "invalid_email"),
    ),

  whatsapp: z
    .string()
    .optional()
    .transform((v) => {
      const cleaned = v == null ? "" : sanitizeLine(v);
      return cleaned ? normalizeWhatsapp(cleaned) : undefined;
    })
    .pipe(z.string().regex(WHATSAPP_RE, "invalid_whatsapp").optional()),

  service_interest: optionalCode(),
  budget_range: optionalCode(),
  timeline: optionalCode(),

  message: z
    .string()
    .transform(sanitizeMultiline)
    .pipe(
      z
        .string()
        .min(1, "required")
        .min(10, "too_short")
        .max(5000, "too_long")
        .refine(
          (m) => (m.match(/https?:\/\//gi)?.length ?? 0) <= 3,
          "too_many_links",
        ),
    ),

  consent: z.literal(true, { error: "consent_required" }),

  utm_source: lenientTracking(100).optional(),
  utm_medium: lenientTracking(100).optional(),
  utm_campaign: lenientTracking(100).optional(),
  referrer: z
    .unknown()
    .transform((v) => (typeof v === "string" ? cleanReferrer(v) : undefined))
    .optional(),

  // anti-bot
  company_website: z.string().max(200).optional(), // honeypot, handled before parsing
  t: z.number().int().min(0).max(86_400_000), // ms the form was open
  turnstile_token: z.string().min(1, "captcha_required").max(2048, "invalid"),
});

export type InquiryInput = z.infer<typeof inquirySchema>;

const REQUIRED_FIELDS = new Set([
  "division",
  "locale",
  "name",
  "org_type",
  "email",
  "message",
  "consent",
  "t",
  "turnstile_token",
]);
const KNOWN_CODE = /^[a-z_]+$/;

export type ParseResult =
  | { ok: true; data: InquiryInput }
  | { ok: false; fields: Record<string, ErrorCode> };

export function parseInquiry(body: unknown): ParseResult {
  const result = inquirySchema.safeParse(body);
  if (result.success) return { ok: true, data: result.data };

  const fields: Record<string, ErrorCode> = {};
  for (const issue of result.error.issues) {
    if (issue.code === "unrecognized_keys") {
      fields._form ??= "unexpected_field";
      continue;
    }
    const field = String(issue.path[0] ?? "_form");
    if (field in fields) continue; // first issue per field wins
    let code: ErrorCode;
    if (KNOWN_CODE.test(issue.message)) {
      code = issue.message as ErrorCode;
    } else if (issue.code === "invalid_type") {
      code = REQUIRED_FIELDS.has(field) ? "required" : "invalid";
    } else {
      code = "invalid";
    }
    fields[field] = code;
  }
  return { ok: false, fields };
}

import { ConfigError, parseOriginMap, type OriginMap } from "./origin";

export { ConfigError };

export interface Inboxes {
  tech: string;
  media: string;
  inquiry: string;
}
export interface MailConfig {
  apiKey: string;
  from: string;
  inboxes: Inboxes;
}

export interface AppEnv {
  supabaseUrl: string;
  serviceRoleKey: string;
  rateLimitSalt: string;
  origins: OriginMap;
  /** Turnstile hostname check is enforced in production only (test keys report example.com). */
  enforceHostname: boolean;
  dashboardUrl?: string;
  /** undefined = captcha OFF. Honeypot, timing trap and rate limits still apply. */
  turnstileSecret?: string;
  /** null = email OFF. Inquiries are still stored; nobody is notified. */
  mail: MailConfig | null;
}

type Source = Record<string, string | undefined>;

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAIL_KEYS = [
  "RESEND_API_KEY",
  "MAIL_FROM",
  "INBOX_TECH",
  "INBOX_MEDIA",
  "INBOX_INQUIRY",
];

/**
 * Fails closed with the NAMES of problems, never the values.
 * The service-role key lives only here, server-side: this project has no
 * client bundle, and any VITE_* secret is rejected outright.
 *
 * Optional features switch on by simply setting their variables:
 *   TURNSTILE_SECRET_KEY                      -> captcha
 *   RESEND_API_KEY + MAIL_FROM + INBOX_*      -> email notifications and acknowledgments
 */
export function loadEnv(src: Source): AppEnv {
  const leaked = Object.keys(src).filter((k) =>
    /^VITE_.*(SERVICE|SECRET|PRIVATE)/i.test(k),
  );
  if (leaked.length > 0) {
    throw new ConfigError(
      `Secret-looking VITE_ variable(s) must not exist: ${leaked.join(", ")}`,
    );
  }

  const required = [
    "SUPABASE_URL",
    "SUPABASE_SERVICE_ROLE_KEY",
    "RATE_LIMIT_SALT",
    "ALLOWED_ORIGINS",
  ];
  const missing = required.filter((k) => !src[k]?.trim());
  if (missing.length > 0)
    throw new ConfigError(`Missing env: ${missing.join(", ")}`);

  const get = (k: string) => (src[k] as string).trim();

  if (!get("SUPABASE_URL").startsWith("https://"))
    throw new ConfigError("SUPABASE_URL must be https");
  if (get("RATE_LIMIT_SALT").length < 16)
    throw new ConfigError("RATE_LIMIT_SALT must be at least 16 characters");

  // Email is all-or-nothing: a half-configured setup would silently drop notifications.
  let mail: MailConfig | null = null;
  const mailSet = MAIL_KEYS.filter((k) => src[k]?.trim());
  if (mailSet.length > 0) {
    const mailMissing = MAIL_KEYS.filter((k) => !src[k]?.trim());
    if (mailMissing.length > 0)
      throw new ConfigError(
        `Email is half-configured, missing: ${mailMissing.join(", ")}`,
      );
    for (const k of ["INBOX_TECH", "INBOX_MEDIA", "INBOX_INQUIRY"]) {
      if (!EMAIL.test(get(k)))
        throw new ConfigError(`${k} must be an email address`);
    }
    if (!get("MAIL_FROM").includes("@"))
      throw new ConfigError("MAIL_FROM must contain an email address");
    mail = {
      apiKey: get("RESEND_API_KEY"),
      from: get("MAIL_FROM"),
      inboxes: {
        tech: get("INBOX_TECH"),
        media: get("INBOX_MEDIA"),
        inquiry: get("INBOX_INQUIRY"),
      },
    };
  }

  return {
    supabaseUrl: get("SUPABASE_URL").replace(/\/+$/, ""),
    serviceRoleKey: get("SUPABASE_SERVICE_ROLE_KEY"),
    rateLimitSalt: get("RATE_LIMIT_SALT"),
    origins: parseOriginMap(src.ALLOWED_ORIGINS),
    enforceHostname: src.VERCEL_ENV === "production",
    dashboardUrl: src.DASHBOARD_URL?.trim() || undefined,
    turnstileSecret: src.TURNSTILE_SECRET_KEY?.trim() || undefined,
    mail,
  };
}

import { ConfigError, parseOriginMap, type OriginMap } from "./origin";

export { ConfigError };

export interface AppEnv {
  supabaseUrl: string;
  serviceRoleKey: string;
  turnstileSecret: string;
  resendApiKey: string;
  mailFrom: string;
  inboxes: { tech: string; media: string; inquiry: string };
  rateLimitSalt: string;
  origins: OriginMap;
  /** Turnstile hostname check is enforced in production only (test keys report example.com). */
  enforceHostname: boolean;
  dashboardUrl?: string;
}

type Source = Record<string, string | undefined>;

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Fails closed with the NAMES of problems, never the values.
 * The service-role key lives only here, server-side: this project has no
 * client bundle, and any VITE_* secret is rejected outright.
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
    "TURNSTILE_SECRET_KEY",
    "RESEND_API_KEY",
    "MAIL_FROM",
    "INBOX_TECH",
    "INBOX_MEDIA",
    "INBOX_INQUIRY",
    "RATE_LIMIT_SALT",
    "ALLOWED_ORIGINS",
  ];
  const missing = required.filter((k) => !src[k]?.trim());
  if (missing.length > 0)
    throw new ConfigError(`Missing env: ${missing.join(", ")}`);

  const get = (k: string) => (src[k] as string).trim();

  if (!get("SUPABASE_URL").startsWith("https://")) {
    throw new ConfigError("SUPABASE_URL must be https");
  }
  if (get("RATE_LIMIT_SALT").length < 16) {
    throw new ConfigError("RATE_LIMIT_SALT must be at least 16 characters");
  }
  for (const k of ["INBOX_TECH", "INBOX_MEDIA", "INBOX_INQUIRY"]) {
    if (!EMAIL.test(get(k)))
      throw new ConfigError(`${k} must be an email address`);
  }
  if (!get("MAIL_FROM").includes("@"))
    throw new ConfigError("MAIL_FROM must contain an email address");

  return {
    supabaseUrl: get("SUPABASE_URL").replace(/\/+$/, ""),
    serviceRoleKey: get("SUPABASE_SERVICE_ROLE_KEY"),
    turnstileSecret: get("TURNSTILE_SECRET_KEY"),
    resendApiKey: get("RESEND_API_KEY"),
    mailFrom: get("MAIL_FROM"),
    inboxes: {
      tech: get("INBOX_TECH"),
      media: get("INBOX_MEDIA"),
      inquiry: get("INBOX_INQUIRY"),
    },
    rateLimitSalt: get("RATE_LIMIT_SALT"),
    origins: parseOriginMap(src.ALLOWED_ORIGINS),
    enforceHostname: src.VERCEL_ENV === "production",
    dashboardUrl: src.DASHBOARD_URL?.trim() || undefined,
  };
}

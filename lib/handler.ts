import { createHmac } from "node:crypto";
import type { AppEnv } from "./env";
import type { Mailer } from "./mail";
import { resolveOrigin } from "./origin";
import { parseInquiry, type InquiryInput } from "./schema";
import {
  buildAckEmail,
  buildInternalEmail,
  type NotifyInput,
} from "./templates";
import type { TurnstileVerdict } from "./turnstile";

/** Minimal structural types so tests don't need @vercel/node. VercelRequest/Response satisfy them. */
export interface ReqLike {
  method?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
}
export interface ResLike {
  status(code: number): ResLike;
  setHeader(name: string, value: string | number): unknown;
  json(body: unknown): unknown;
  end(): unknown;
}

export interface SubmitArgs {
  input: InquiryInput;
  sourceSite: string;
}
export interface SubmitResult {
  id: string;
  ref: string;
  isDuplicate: boolean;
}
/** Thrown by deps.submit when Postgres raised one of our validation errors. */
export class RpcValidationError extends Error {}

export interface Deps {
  env: AppEnv;
  rateLimit(
    key: string,
    limit: number,
    windowSeconds: number,
  ): Promise<boolean>;
  verifyTurnstile(args: {
    token: string;
    ip?: string;
    expectedHostname?: string;
  }): Promise<TurnstileVerdict>;
  submit(args: SubmitArgs): Promise<SubmitResult>;
  /** null = email off (lite mode). */
  mail: Mailer | null;
  logEvent(
    inquiryId: string,
    type: string,
    detail: Record<string, unknown>,
  ): Promise<void>;
  log(
    level: "info" | "warn" | "error",
    event: string,
    meta?: Record<string, unknown>,
  ): void;
}

export const LIMITS = {
  maxBodyBytes: 16 * 1024,
  minFormMs: 1500,
  ip: { limit: 6, windowSeconds: 600 },
  email: { limit: 3, windowSeconds: 3600 },
  global: { limit: 300, windowSeconds: 3600 },
} as const;

const header = (req: ReqLike, name: string): string | undefined => {
  const v = req.headers[name];
  return Array.isArray(v) ? v[0] : v;
};

function clientIp(req: ReqLike): string | undefined {
  // On Vercel these are set by the platform edge, not by the client.
  return (
    header(req, "x-real-ip") ??
    header(req, "x-forwarded-for")?.split(",")[0]?.trim() ??
    undefined
  );
}

export function createHandler(deps: Deps) {
  const { env } = deps;
  const hash = (value: string) =>
    createHmac("sha256", env.rateLimitSalt)
      .update(value)
      .digest("hex")
      .slice(0, 32);

  return async function handler(req: ReqLike, res: ResLike): Promise<void> {
    const reply = (status: number, body: Record<string, unknown>) => {
      res.status(status).json(body);
    };

    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");

    const match = resolveOrigin(header(req, "origin"), env.origins);
    if (match) {
      res.setHeader("Access-Control-Allow-Origin", match.origin);
      res.setHeader("Vary", "Origin");
    }

    if (req.method === "OPTIONS") {
      if (!match) return reply(403, { ok: false, error: "forbidden_origin" });
      res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type");
      res.setHeader("Access-Control-Max-Age", 86400);
      res.status(204).end();
      return;
    }

    // CORS is not authentication (non-browser clients can send any Origin). It
    // keeps other websites out; Turnstile + rate limits are what stop scripts.
    if (!match) return reply(403, { ok: false, error: "forbidden_origin" });

    if (req.method !== "POST") {
      res.setHeader("Allow", "POST, OPTIONS");
      return reply(405, { ok: false, error: "method_not_allowed" });
    }

    if (
      !(header(req, "content-type") ?? "")
        .toLowerCase()
        .startsWith("application/json")
    ) {
      return reply(415, { ok: false, error: "unsupported_media_type" });
    }
    const declared = Number(header(req, "content-length") ?? 0);
    if (Number.isFinite(declared) && declared > LIMITS.maxBodyBytes) {
      return reply(413, { ok: false, error: "payload_too_large" });
    }

    let body: unknown;
    try {
      body = req.body; // Vercel parses lazily and throws on malformed JSON
    } catch {
      return reply(400, { ok: false, error: "invalid_json" });
    }
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      return reply(400, { ok: false, error: "invalid_json" });
    }

    // ---- bots get a convincing success and nothing else ---------------------
    const raw = body as Record<string, unknown>;
    const honeypot =
      typeof raw.company_website === "string" &&
      raw.company_website.trim() !== "";
    const tooFast = typeof raw.t === "number" && raw.t < LIMITS.minFormMs;
    if (honeypot || tooFast) {
      deps.log("info", "bot_trapped", {
        reason: honeypot ? "honeypot" : "too_fast",
      });
      return reply(201, { ok: true, ref: null });
    }

    // ---- validation ----------------------------------------------------------
    const parsed = parseInquiry(body);
    if (!parsed.ok)
      return reply(422, {
        ok: false,
        error: "validation",
        fields: parsed.fields,
      });
    const input = parsed.data;

    // Captcha is optional infrastructure: with no secret configured it is skipped entirely.
    const captchaOn = Boolean(env.turnstileSecret);
    if (captchaOn && !input.turnstile_token) {
      return reply(422, {
        ok: false,
        error: "validation",
        fields: { turnstile_token: "captcha_required" },
      });
    }

    // ---- abuse controls ------------------------------------------------------
    const ip = clientIp(req);
    try {
      if (
        !(await deps.rateLimit(
          `ip:${hash(ip ?? "unknown")}`,
          LIMITS.ip.limit,
          LIMITS.ip.windowSeconds,
        ))
      ) {
        res.setHeader("Retry-After", LIMITS.ip.windowSeconds);
        return reply(429, {
          ok: false,
          error: "rate_limited",
          retryAfter: LIMITS.ip.windowSeconds,
        });
      }
    } catch {
      deps.log("error", "rate_limit_unavailable");
      return reply(503, { ok: false, error: "unavailable" });
    }

    const verdict = captchaOn
      ? await deps.verifyTurnstile({
          token: input.turnstile_token as string,
          ip,
          expectedHostname: env.enforceHostname ? match.hostname : undefined,
        })
      : "ok";
    if (verdict === "unavailable") {
      deps.log("error", "turnstile_unavailable");
      return reply(503, { ok: false, error: "unavailable" });
    }
    if (verdict === "failed")
      return reply(400, { ok: false, error: "captcha_failed" });

    // These two count only solved-captcha requests, so a bot cannot burn a
    // victim's per-email quota or the global quota without passing Turnstile.
    try {
      const checks: Array<[string, { limit: number; windowSeconds: number }]> =
        [
          [`em:${hash(input.email)}`, LIMITS.email],
          ["global", LIMITS.global],
        ];
      for (const [key, rule] of checks) {
        if (!(await deps.rateLimit(key, rule.limit, rule.windowSeconds))) {
          res.setHeader("Retry-After", rule.windowSeconds);
          return reply(429, {
            ok: false,
            error: "rate_limited",
            retryAfter: rule.windowSeconds,
          });
        }
      }
    } catch {
      deps.log("error", "rate_limit_unavailable");
      return reply(503, { ok: false, error: "unavailable" });
    }

    // ---- persist ----------------------------------------------------------------
    let saved: SubmitResult;
    try {
      saved = await deps.submit({ input, sourceSite: match.site });
    } catch (error) {
      if (error instanceof RpcValidationError) {
        return reply(422, {
          ok: false,
          error: "validation",
          fields: { _form: "invalid" },
        });
      }
      deps.log("error", "submit_failed"); // no body, no PII in logs
      return reply(500, { ok: false, error: "server_error" });
    }

    if (saved.isDuplicate) return reply(200, { ok: true, ref: saved.ref });

    // The row is the source of truth. Mail problems are recorded, never surfaced.
    await notify(deps, saved, input, match.site);

    return reply(201, { ok: true, ref: saved.ref });
  };
}

async function notify(
  deps: Deps,
  saved: SubmitResult,
  input: InquiryInput,
  sourceSite: string,
): Promise<void> {
  const mailer = deps.mail;
  const mailConfig = deps.env.mail;
  if (!mailer || !mailConfig) return; // email off: the stored row is the whole result

  const mailEnv = {
    inboxes: mailConfig.inboxes,
    dashboardUrl: deps.env.dashboardUrl,
  };
  const n: NotifyInput = {
    ref: saved.ref,
    division: input.division,
    locale: input.locale,
    sourceSite,
    name: input.name,
    organization: input.organization,
    orgType: input.org_type,
    email: input.email,
    whatsapp: input.whatsapp,
    serviceInterest: input.service_interest,
    budgetRange: input.budget_range,
    timeline: input.timeline,
    message: input.message,
    conflict: input.org_type === "public_figure",
    utmSource: input.utm_source,
    utmMedium: input.utm_medium,
    utmCampaign: input.utm_campaign,
    referrer: input.referrer,
  };

  const jobs: Array<
    [string, string, Promise<{ ok: boolean; status: number }>]
  > = [
    ["notified", "notify_failed", mailer.send(buildInternalEmail(n, mailEnv))],
    ["ack_sent", "ack_failed", mailer.send(buildAckEmail(n, mailEnv))],
  ];

  await Promise.all(
    jobs.map(async ([okType, failType, job]) => {
      const result = await job;
      if (!result.ok)
        deps.log("error", failType, { ref: saved.ref, status: result.status });
      await deps
        .logEvent(saved.id, result.ok ? okType : failType, {
          status: result.status,
        })
        .catch(() => deps.log("error", "event_log_failed", { ref: saved.ref }));
    }),
  );
}

import { createClient } from "@supabase/supabase-js";
import type { AppEnv } from "./env";
import { createHandler, RpcValidationError, type Deps } from "./handler";
import { createResendMailer } from "./mail";
import { verifyTurnstile } from "./turnstile";

/** Postgres errcode our RPCs raise for validation failures (see submit_inquiry). */
const VALIDATION_SQLSTATE = "22023";

export function createRealDeps(env: AppEnv): Deps {
  // Service-role client: server-side only, no session persistence.
  const supabase = createClient(env.supabaseUrl, env.serviceRoleKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    },
  });
  const intake = () => supabase.schema("intake");

  return {
    env,

    async rateLimit(key, limit, windowSeconds) {
      const { data, error } = await intake().rpc("check_rate_limit", {
        p_key: key,
        p_limit: limit,
        p_window_seconds: windowSeconds,
      });
      if (error) throw new Error("rate_limit_rpc_failed");
      return data === true;
    },

    verifyTurnstile: ({ token, ip, expectedHostname }) =>
      verifyTurnstile({
        secret: env.turnstileSecret,
        token,
        ip,
        expectedHostname,
      }),

    async submit({ input, sourceSite }) {
      const { data, error } = await intake().rpc("submit_inquiry", {
        p_division: input.division,
        p_source_site: sourceSite,
        p_locale: input.locale,
        p_name: input.name,
        p_org_type: input.org_type,
        p_email: input.email,
        p_message: input.message,
        p_consent: input.consent,
        p_organization: input.organization ?? null,
        p_whatsapp: input.whatsapp ?? null,
        p_service_interest: input.service_interest ?? null,
        p_budget_range: input.budget_range ?? null,
        p_timeline: input.timeline ?? null,
        p_utm_source: input.utm_source ?? null,
        p_utm_medium: input.utm_medium ?? null,
        p_utm_campaign: input.utm_campaign ?? null,
        p_referrer: input.referrer ?? null,
      });
      if (error) {
        if (error.code === VALIDATION_SQLSTATE)
          throw new RpcValidationError(error.message);
        throw new Error("submit_rpc_failed");
      }
      const row = Array.isArray(data) ? data[0] : data;
      if (!row?.o_ref_no || !row?.o_id) throw new Error("submit_rpc_empty");
      return {
        id: row.o_id as string,
        ref: row.o_ref_no as string,
        isDuplicate: row.o_is_duplicate === true,
      };
    },

    mail: createResendMailer(env.resendApiKey, env.mailFrom),

    async logEvent(inquiryId, type, detail) {
      const { error } = await intake()
        .from("inquiry_events")
        .insert({ inquiry_id: inquiryId, event_type: type, detail });
      if (error) throw new Error("event_insert_failed");
    },

    log(level, event, meta = {}) {
      // Structured, PII-free: refs, codes and statuses only.
      console[level === "info" ? "log" : level](
        JSON.stringify({ evt: event, ...meta }),
      );
    },
  };
}

export { createHandler };

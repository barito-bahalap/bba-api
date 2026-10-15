export type TurnstileVerdict = "ok" | "failed" | "unavailable";

interface SiteverifyResponse {
  success?: boolean;
  hostname?: string;
  "error-codes"?: string[];
}

export interface VerifyArgs {
  secret: string;
  token: string;
  ip?: string;
  /** When set, the token must have been issued for this hostname. */
  expectedHostname?: string;
  fetchImpl?: typeof fetch;
}

/**
 * "failed"      the token is invalid, expired, reused, or for another site -> 400
 * "unavailable" Cloudflare could not be reached / answered nonsense        -> 503
 * Never returns "ok" unless Cloudflare explicitly said success.
 */
export async function verifyTurnstile({
  secret,
  token,
  ip,
  expectedHostname,
  fetchImpl = fetch,
}: VerifyArgs): Promise<TurnstileVerdict> {
  try {
    const response = await fetchImpl(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          secret,
          response: token,
          ...(ip ? { remoteip: ip } : {}),
          idempotency_key: crypto.randomUUID(),
        }),
        signal: AbortSignal.timeout(5000),
      },
    );
    if (!response.ok) return "unavailable";

    const data = (await response.json()) as SiteverifyResponse;
    if (data.success !== true) return "failed";
    if (expectedHostname && data.hostname !== expectedHostname) return "failed";
    return "ok";
  } catch {
    return "unavailable";
  }
}

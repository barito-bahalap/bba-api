export interface MailMessage {
  to: string[];
  subject: string;
  text: string;
  html: string;
  replyTo?: string;
  /** Stops a retry from sending the same mail twice. */
  idempotencyKey?: string;
}

export interface Mailer {
  send(message: MailMessage): Promise<{ ok: boolean; status: number }>;
}

/** Resend over plain fetch: no SDK, 4 s timeout, never throws. */
export function createResendMailer(
  apiKey: string,
  from: string,
  fetchImpl: typeof fetch = fetch,
): Mailer {
  return {
    async send(message) {
      try {
        const response = await fetchImpl("https://api.resend.com/emails", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${apiKey}`,
            "Content-Type": "application/json",
            ...(message.idempotencyKey
              ? { "Idempotency-Key": message.idempotencyKey }
              : {}),
          },
          body: JSON.stringify({
            from,
            to: message.to,
            subject: message.subject,
            text: message.text,
            html: message.html,
            ...(message.replyTo ? { reply_to: message.replyTo } : {}),
          }),
          signal: AbortSignal.timeout(4000),
        });
        return { ok: response.ok, status: response.status };
      } catch {
        return { ok: false, status: 0 };
      }
    },
  };
}

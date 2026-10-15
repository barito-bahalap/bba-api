import type { Division, Locale, OrgType } from "./schema";
import type { AppEnv } from "./env";
import type { MailMessage } from "./mail";

export interface NotifyInput {
  ref: string;
  division: Division;
  locale: Locale;
  sourceSite: string;
  name: string;
  organization?: string;
  orgType: OrgType;
  email: string;
  whatsapp?: string;
  serviceInterest?: string;
  budgetRange?: string;
  timeline?: string;
  message: string;
  conflict: boolean;
  utmSource?: string;
  utmMedium?: string;
  utmCampaign?: string;
  referrer?: string;
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const TAG: Record<Division, string> = {
  bbt: "BBT",
  bbm: "BBM",
  partnership: "PARTNERSHIP",
  general: "GENERAL",
};

/** Which role inbox owns an inquiry. BBT mail never lands in media@ and vice versa. */
export function inboxFor(
  division: Division,
  inboxes: AppEnv["inboxes"],
): string {
  if (division === "bbt") return inboxes.tech;
  if (division === "bbm") return inboxes.media;
  return inboxes.inquiry;
}

export function recipientsFor(
  i: Pick<NotifyInput, "division" | "conflict">,
  inboxes: AppEnv["inboxes"],
): string[] {
  const primary = inboxFor(i.division, inboxes);
  // Conflict-flagged inquiries always reach the founder inbox as well.
  return i.conflict && primary !== inboxes.inquiry
    ? [primary, inboxes.inquiry]
    : [primary];
}

export function buildInternalEmail(
  i: NotifyInput,
  env: Pick<AppEnv, "inboxes" | "dashboardUrl">,
): MailMessage {
  const rows: Array<[string, string | undefined]> = [
    ["Reference", i.ref],
    ["Division", i.division],
    ["Source site", i.sourceSite],
    ["Locale", i.locale],
    ["Name", i.name],
    ["Organization", i.organization],
    ["Org type", i.orgType],
    ["Email", i.email],
    ["WhatsApp", i.whatsapp],
    ["Service interest", i.serviceInterest],
    ["Budget", i.budgetRange],
    ["Timeline", i.timeline],
    [
      "UTM",
      [i.utmSource, i.utmMedium, i.utmCampaign].filter(Boolean).join(" / ") ||
        undefined,
    ],
    ["Referrer", i.referrer],
  ];
  const present = rows.filter((r): r is [string, string] => Boolean(r[1]));

  const flag = i.conflict
    ? "CONFLICT REVIEW: public figure. Founder must clear this before any engagement."
    : undefined;
  const subjectLine =
    `${i.conflict ? "[REVIEW: PUBLIC FIGURE] " : ""}[${TAG[i.division]}] ${i.ref} · ${i.name}${
      i.organization ? ` (${i.organization})` : ""
    }`.slice(0, 200);

  const link = env.dashboardUrl
    ? `\nOpen in dashboard: ${env.dashboardUrl}`
    : "";

  const text = [
    flag,
    ...present.map(([k, v]) => `${k}: ${v}`),
    "",
    "Message:",
    i.message,
    link,
    "",
    "Reply to this email to answer the sender directly. SLA: respond within 24 hours.",
  ]
    .filter((x) => x !== undefined)
    .join("\n");

  const html = `<!doctype html><html><body style="font-family:system-ui,sans-serif;font-size:14px;color:#111">
${flag ? `<p style="background:#fff3cd;border:1px solid #e0c36a;padding:10px;border-radius:6px"><strong>${escapeHtml(flag)}</strong></p>` : ""}
<table cellpadding="6" style="border-collapse:collapse">
${present.map(([k, v]) => `<tr><td style="color:#555;vertical-align:top">${escapeHtml(k)}</td><td>${escapeHtml(v)}</td></tr>`).join("\n")}
</table>
<p style="margin:16px 0 4px;color:#555">Message</p>
<pre style="white-space:pre-wrap;font-family:inherit;background:#f6f6f6;padding:12px;border-radius:6px">${escapeHtml(i.message)}</pre>
${env.dashboardUrl ? `<p><a href="${escapeHtml(env.dashboardUrl)}">Open in dashboard</a></p>` : ""}
<p style="color:#777">Reply to this email to answer the sender directly. SLA: respond within 24 hours.</p>
</body></html>`;

  return {
    to: recipientsFor(i, env.inboxes),
    subject: subjectLine,
    text,
    html,
    replyTo: i.email,
    idempotencyKey: `${i.ref}:internal`,
  };
}

const BRAND: Record<Division, string> = {
  bbt: "Barito Bahalap Technology",
  bbm: "Barito Bahalap Media",
  partnership: "Barito Bahalap Agency",
  general: "Barito Bahalap Agency",
};

const COPY: Record<
  Locale,
  {
    subject: (ref: string) => string;
    hello: (name: string) => string;
    body: (brand: string) => string;
    refLabel: string;
    commitment: string;
    ignore: string;
    signoff: string;
  }
> = {
  id: {
    subject: (ref) => `Permintaan Anda telah kami terima · ${ref}`,
    hello: (name) => `Halo ${name},`,
    body: (brand) =>
      `Terima kasih telah menghubungi ${brand}. Permintaan Anda sudah kami terima.`,
    refLabel: "Nomor referensi",
    commitment: "Tim kami akan menanggapi dalam 24 jam.",
    ignore:
      "Jika Anda tidak pernah mengirim permintaan ini, abaikan saja email ini.",
    signoff: "Salam, Tim Barito Bahalap",
  },
  en: {
    subject: (ref) => `We received your inquiry · ${ref}`,
    hello: (name) => `Hello ${name},`,
    body: (brand) =>
      `Thank you for contacting ${brand}. We have received your inquiry.`,
    refLabel: "Reference number",
    commitment: "Our team will respond within 24 hours.",
    ignore:
      "If you did not submit this inquiry, you can safely ignore this email.",
    signoff: "Regards, The Barito Bahalap team",
  },
};

export function buildAckEmail(
  i: NotifyInput,
  env: Pick<AppEnv, "inboxes">,
): MailMessage {
  const c = COPY[i.locale];
  const brand = BRAND[i.division];
  const text = [
    c.hello(i.name),
    "",
    c.body(brand),
    "",
    `${c.refLabel}: ${i.ref}`,
    c.commitment,
    "",
    c.ignore,
    "",
    c.signoff,
  ].join("\n");

  const html = `<!doctype html><html><body style="font-family:system-ui,sans-serif;font-size:15px;color:#111;line-height:1.5">
<p>${escapeHtml(c.hello(i.name))}</p>
<p>${escapeHtml(c.body(brand))}</p>
<p style="background:#f6f6f6;padding:12px 16px;border-radius:6px;display:inline-block">
${escapeHtml(c.refLabel)}<br><strong style="font-size:18px;font-family:ui-monospace,monospace">${escapeHtml(i.ref)}</strong></p>
<p><strong>${escapeHtml(c.commitment)}</strong></p>
<p style="color:#666">${escapeHtml(c.ignore)}</p>
<p>${escapeHtml(c.signoff)}</p>
</body></html>`;

  return {
    to: [i.email],
    subject: c.subject(i.ref),
    text,
    html,
    // Replies reach the owning role inbox, not a no-reply black hole.
    replyTo: inboxFor(i.division, env.inboxes),
    idempotencyKey: `${i.ref}:ack`,
  };
}

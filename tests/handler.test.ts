import assert from "node:assert/strict";
import { beforeEach, describe, it } from "node:test";
import {
  createHandler,
  RpcValidationError,
  type Deps,
  type ReqLike,
  type ResLike,
} from "@/lib/handler";
import { loadEnv } from "@/lib/env";
import type { MailMessage } from "@/lib/mail";
import { buildAckEmail, buildInternalEmail, escapeHtml } from "@/lib/templates";
import { verifyTurnstile } from "@/lib/turnstile";

const env = loadEnv({
  SUPABASE_URL: "https://x.supabase.co",
  SUPABASE_SERVICE_ROLE_KEY: "k",
  TURNSTILE_SECRET_KEY: "s",
  RESEND_API_KEY: "r",
  MAIL_FROM: "BBA <no-reply@notify.example.com>",
  INBOX_TECH: "tech@example.com",
  INBOX_MEDIA: "media@example.com",
  INBOX_INQUIRY: "inquiry@example.com",
  RATE_LIMIT_SALT: "0123456789abcdef",
  ALLOWED_ORIGINS: JSON.stringify({
    "https://example.com": "corporate",
    "https://tech.example.com": "tech",
    "https://media.example.com": "media",
  }),
});

const body = {
  division: "bbt",
  locale: "en",
  name: "Ana Tester",
  org_type: "corporate",
  organization: "PT Contoh",
  email: "ana@example.com",
  whatsapp: "081234567890",
  message: "We would like a dashboard for our regional team.",
  consent: true,
  t: 9000,
  turnstile_token: "tok",
};

class FakeRes implements ResLike {
  code = 0;
  headers: Record<string, string | number> = {};
  payload: any;
  status(code: number) {
    this.code = code;
    return this;
  }
  setHeader(name: string, value: string | number) {
    this.headers[name] = value;
    return this;
  }
  json(b: unknown) {
    this.payload = b;
    return this;
  }
  end() {
    return this;
  }
}

interface Calls {
  rate: string[];
  turnstile: number;
  submit: any[];
  mail: MailMessage[];
  events: Array<[string, string]>;
  logs: string[];
}

let calls: Calls;
let overrides: Partial<Deps>;

const makeDeps = (): Deps => ({
  env,
  async rateLimit(key) {
    calls.rate.push(key);
    return true;
  },
  async verifyTurnstile() {
    calls.turnstile += 1;
    return "ok";
  },
  async submit(args) {
    calls.submit.push(args);
    return { id: "uuid-1", ref: "INQ/2026/1015/001", isDuplicate: false };
  },
  mail: {
    async send(m) {
      calls.mail.push(m);
      return { ok: true, status: 200 };
    },
  },
  async logEvent(id, type) {
    calls.events.push([id, type]);
  },
  log(_l, event) {
    calls.logs.push(event);
  },
  ...overrides,
});

const post = async (
  b: unknown,
  headers: Record<string, string> = {},
  method = "POST",
) => {
  const res = new FakeRes();
  const req: ReqLike = {
    method,
    headers: {
      origin: "https://tech.example.com",
      "content-type": "application/json",
      "x-real-ip": "203.0.113.9",
      ...headers,
    },
    body: b,
  };
  await createHandler(makeDeps())(req, res);
  return res;
};

beforeEach(() => {
  calls = {
    rate: [],
    turnstile: 0,
    submit: [],
    mail: [],
    events: [],
    logs: [],
  };
  overrides = {};
});

describe("CORS and request shape", () => {
  it("answers preflight only for allow-listed origins", async () => {
    const ok = await post(undefined, {}, "OPTIONS");
    assert.equal(ok.code, 204);
    assert.equal(
      ok.headers["Access-Control-Allow-Origin"],
      "https://tech.example.com",
    );
    const bad = await post(
      undefined,
      { origin: "https://evil.example" },
      "OPTIONS",
    );
    assert.equal(bad.code, 403);
    assert.equal(bad.headers["Access-Control-Allow-Origin"], undefined);
  });

  it("rejects unknown, missing and look-alike origins", async () => {
    for (const origin of [
      "https://evil.example",
      "https://tech.example.com.evil.io",
      "null",
      "http://tech.example.com",
    ]) {
      assert.equal((await post(body, { origin })).code, 403, origin);
    }
    const noOrigin = new FakeRes();
    await createHandler(makeDeps())(
      { method: "POST", headers: { "content-type": "application/json" }, body },
      noOrigin,
    );
    assert.equal(noOrigin.code, 403);
    assert.equal(calls.submit.length, 0);
  });

  it("allows only POST", async () => {
    const res = await post(undefined, {}, "GET");
    assert.equal(res.code, 405);
    assert.equal(res.headers.Allow, "POST, OPTIONS");
  });

  it("enforces content type and size", async () => {
    assert.equal(
      (await post(body, { "content-type": "text/plain" })).code,
      415,
    );
    assert.equal((await post(body, { "content-length": "999999" })).code, 413);
  });

  it("rejects non-object bodies", async () => {
    assert.equal((await post("nope")).code, 400);
    assert.equal((await post([1])).code, 400);
  });
});

describe("bot traps", () => {
  it("returns a fake success for a filled honeypot and does nothing", async () => {
    const res = await post({ ...body, company_website: "http://spam.example" });
    assert.equal(res.code, 201);
    assert.equal(res.payload.ref, null);
    assert.deepEqual(
      [
        calls.turnstile,
        calls.submit.length,
        calls.mail.length,
        calls.rate.length,
      ],
      [0, 0, 0, 0],
    );
  });
  it("does the same for implausibly fast submissions", async () => {
    const res = await post({ ...body, t: 200 });
    assert.equal(res.code, 201);
    assert.equal(calls.submit.length, 0);
  });
  it("does not reveal validation errors to bots", async () => {
    const res = await post({ company_website: "x" });
    assert.equal(res.code, 201);
  });
});

describe("validation", () => {
  it("returns field codes and touches nothing else", async () => {
    const res = await post({ ...body, email: "nope", name: "" });
    assert.equal(res.code, 422);
    assert.equal(res.payload.fields.email, "invalid_email");
    assert.equal(res.payload.fields.name, "required");
    assert.deepEqual(
      [calls.turnstile, calls.rate.length, calls.submit.length],
      [0, 0, 0],
    );
  });
  it("refuses a client-supplied source_site", async () => {
    const res = await post({ ...body, source_site: "media" });
    assert.equal(res.code, 422);
  });
});

describe("abuse controls", () => {
  it("rate-limits per IP before spending a Turnstile call", async () => {
    overrides.rateLimit = async (key) => {
      calls.rate.push(key);
      return false;
    };
    const res = await post(body);
    assert.equal(res.code, 429);
    assert.equal(res.headers["Retry-After"], 600);
    assert.equal(calls.turnstile, 0);
    assert.equal(calls.submit.length, 0);
  });

  it("stores no raw IP or email in rate-limit keys", async () => {
    await post(body);
    assert.equal(calls.rate.length, 3);
    for (const key of calls.rate) {
      assert.ok(
        !key.includes("203.0.113.9") && !key.includes("ana@example.com"),
        key,
      );
    }
  });

  it("applies per-email and global limits only after Turnstile passes", async () => {
    overrides.verifyTurnstile = async () => {
      calls.turnstile += 1;
      return "failed";
    };
    const res = await post(body);
    assert.equal(res.code, 400);
    assert.equal(res.payload.error, "captcha_failed");
    assert.equal(calls.rate.length, 1, "only the IP bucket was touched");
    assert.equal(calls.submit.length, 0);
  });

  it("returns 429 when the email bucket is exhausted", async () => {
    overrides.rateLimit = async (key) => {
      calls.rate.push(key);
      return !key.startsWith("em:");
    };
    const res = await post(body);
    assert.equal(res.code, 429);
    assert.equal(res.headers["Retry-After"], 3600);
    assert.equal(calls.submit.length, 0);
  });

  it("fails closed (503) if Turnstile or the limiter is down", async () => {
    overrides.verifyTurnstile = async () => "unavailable";
    assert.equal((await post(body)).code, 503);
    overrides.verifyTurnstile = undefined;
    overrides.rateLimit = async () => {
      throw new Error("db down");
    };
    assert.equal((await post(body)).code, 503);
    assert.equal(calls.submit.length, 0);
  });

  it("checks the Turnstile hostname only when enforced", async () => {
    let seen: string | undefined = "unset";
    overrides.verifyTurnstile = async (a) => {
      seen = a.expectedHostname;
      return "ok";
    };
    await post(body);
    assert.equal(seen, undefined);
    overrides.env = { ...env, enforceHostname: true };
    await post(body);
    assert.equal(seen, "tech.example.com");
  });
});

describe("success path", () => {
  it("derives source_site from Origin, lowercases email, normalises WhatsApp", async () => {
    const res = await post(body, { origin: "https://media.example.com" });
    assert.equal(res.code, 201);
    assert.deepEqual(res.payload, { ok: true, ref: "INQ/2026/1015/001" });
    assert.equal(calls.submit[0].sourceSite, "media");
    assert.equal(calls.submit[0].input.whatsapp, "+6281234567890");
    assert.equal(res.headers["Cache-Control"], "no-store");
  });

  it("sends the role inbox an internal mail and the sender an acknowledgment", async () => {
    await post(body);
    assert.equal(calls.mail.length, 2);
    const internal = calls.mail.find((m) => m.subject.startsWith("[BBT]"))!;
    assert.deepEqual(internal.to, ["tech@example.com"]);
    assert.equal(internal.replyTo, "ana@example.com");
    const ack = calls.mail.find((m) => m.to[0] === "ana@example.com")!;
    assert.match(ack.text, /INQ\/2026\/1015\/001/);
    assert.match(ack.text, /within 24 hours/);
    assert.equal(ack.replyTo, "tech@example.com");
    assert.deepEqual(calls.events.map((e) => e[1]).sort(), [
      "ack_sent",
      "notified",
    ]);
  });

  it("routes media to media@, partnership/general to inquiry@", async () => {
    await post({ ...body, division: "bbm" });
    assert.deepEqual(
      calls.mail.find((m) => m.subject.startsWith("[BBM]"))!.to,
      ["media@example.com"],
    );
    calls.mail = [];
    await post({ ...body, division: "partnership" });
    assert.deepEqual(
      calls.mail.find((m) => m.subject.startsWith("[PARTNERSHIP]"))!.to,
      ["inquiry@example.com"],
    );
  });

  it("copies inquiry@ and flags the subject for public figures", async () => {
    await post({ ...body, division: "bbm", org_type: "public_figure" });
    const internal = calls.mail.find((m) =>
      m.subject.includes("PUBLIC FIGURE"),
    )!;
    assert.deepEqual(internal.to, ["media@example.com", "inquiry@example.com"]);
    assert.match(internal.text, /CONFLICT REVIEW/);
  });

  it("sends the acknowledgment in the visitor's language", async () => {
    await post({ ...body, locale: "id" });
    const ack = calls.mail.find((m) => m.to[0] === "ana@example.com")!;
    assert.match(ack.text, /dalam 24 jam/);
    assert.match(ack.subject, /Permintaan Anda/);
  });

  it("a mail outage never fails the request, and is recorded", async () => {
    overrides.mail = {
      async send() {
        return { ok: false, status: 500 };
      },
    };
    const res = await post(body);
    assert.equal(res.code, 201);
    assert.deepEqual(calls.events.map((e) => e[1]).sort(), [
      "ack_failed",
      "notify_failed",
    ]);
    assert.ok(calls.logs.includes("notify_failed"));
  });

  it("a duplicate resubmission returns the original ref and sends no mail", async () => {
    overrides.submit = async () => ({
      id: "uuid-1",
      ref: "INQ/2026/1015/001",
      isDuplicate: true,
    });
    const res = await post(body);
    assert.equal(res.code, 200);
    assert.equal(res.payload.ref, "INQ/2026/1015/001");
    assert.equal(calls.mail.length, 0);
  });
});

describe("database errors", () => {
  it("maps RPC validation errors to 422", async () => {
    overrides.submit = async () => {
      throw new RpcValidationError("invalid_email");
    };
    assert.equal((await post(body)).code, 422);
  });
  it("hides everything else behind a generic 500 and logs no PII", async () => {
    overrides.submit = async () => {
      throw new Error("connection refused to db.internal:5432");
    };
    const res = await post(body);
    assert.equal(res.code, 500);
    assert.deepEqual(res.payload, { ok: false, error: "server_error" });
    assert.equal(calls.mail.length, 0);
  });
});

describe("email templates", () => {
  const n = {
    ref: "INQ/2026/1015/001",
    division: "bbt" as const,
    locale: "en" as const,
    sourceSite: "tech",
    name: "Ana <script>alert(1)</script>",
    orgType: "corporate" as const,
    email: "ana@example.com",
    message: '<img src=x onerror=alert(1)> & "quotes"',
    conflict: false,
  };
  it("escapes every user-supplied value in HTML", () => {
    const html =
      buildInternalEmail(n, { inboxes: env.mail!.inboxes }).html +
      buildAckEmail(n, { inboxes: env.mail!.inboxes }).html;
    assert.ok(
      !html.includes("<script>") && !html.includes("<img"),
      "no raw markup",
    );
    assert.ok(
      html.includes(
        "&lt;img src=x onerror=alert(1)&gt; &amp; &quot;quotes&quot;",
      ),
    );
  });
  it("escapeHtml covers the five dangerous characters", () => {
    assert.equal(escapeHtml(`<>&"'`), "&lt;&gt;&amp;&quot;&#39;");
  });
});

describe("verifyTurnstile", () => {
  const reply = (status: number, json: unknown) =>
    (async () =>
      new Response(JSON.stringify(json), {
        status,
      })) as unknown as typeof fetch;
  it("ok only on explicit success", async () => {
    assert.equal(
      await verifyTurnstile({
        secret: "s",
        token: "t",
        fetchImpl: reply(200, { success: true }),
      }),
      "ok",
    );
    assert.equal(
      await verifyTurnstile({
        secret: "s",
        token: "t",
        fetchImpl: reply(200, { success: false }),
      }),
      "failed",
    );
    assert.equal(
      await verifyTurnstile({
        secret: "s",
        token: "t",
        fetchImpl: reply(200, {}),
      }),
      "failed",
    );
  });
  it("checks the hostname when asked", async () => {
    const f = reply(200, { success: true, hostname: "evil.example" });
    assert.equal(
      await verifyTurnstile({
        secret: "s",
        token: "t",
        expectedHostname: "tech.example.com",
        fetchImpl: f,
      }),
      "failed",
    );
  });
  it("is unavailable on network or HTTP errors", async () => {
    assert.equal(
      await verifyTurnstile({
        secret: "s",
        token: "t",
        fetchImpl: reply(500, {}),
      }),
      "unavailable",
    );
    assert.equal(
      await verifyTurnstile({
        secret: "s",
        token: "t",
        fetchImpl: (async () => {
          throw new Error("x");
        }) as unknown as typeof fetch,
      }),
      "unavailable",
    );
  });
});

describe("lite mode (no captcha, no email)", () => {
  const base = {
    SUPABASE_URL: "https://x.supabase.co",
    SUPABASE_SERVICE_ROLE_KEY: "k",
    RATE_LIMIT_SALT: "0123456789abcdef",
    ALLOWED_ORIGINS: '{"https://example.com":"corporate"}',
  };
  const lite = loadEnv(base);
  const { turnstile_token: _drop, ...noToken } = body;

  it("loads with only the four required variables", () => {
    assert.equal(lite.turnstileSecret, undefined);
    assert.equal(lite.mail, null);
  });

  it("refuses a half-configured email setup instead of silently dropping mail", () => {
    assert.throws(
      () => loadEnv({ ...base, RESEND_API_KEY: "r" }),
      /half-configured, missing: MAIL_FROM/,
    );
  });

  it("stores the inquiry, skips Turnstile and sends no mail", async () => {
    overrides.env = lite;
    overrides.mail = null;
    const res = await post(noToken, { origin: "https://example.com" });
    assert.equal(res.code, 201);
    assert.equal(res.payload.ref, "INQ/2026/1015/001");
    assert.equal(calls.submit.length, 1);
    assert.equal(calls.submit[0].sourceSite, "corporate");
    assert.deepEqual(
      [calls.turnstile, calls.mail.length, calls.events.length],
      [0, 0, 0],
    );
  });

  it("still applies honeypot and rate limits", async () => {
    overrides.env = lite;
    overrides.mail = null;
    assert.equal(
      (
        await post(
          { ...noToken, company_website: "x" },
          { origin: "https://example.com" },
        )
      ).payload.ref,
      null,
    );
    overrides.rateLimit = async () => false;
    assert.equal(
      (await post(noToken, { origin: "https://example.com" })).code,
      429,
    );
  });

  it("with captcha ON, a missing token is rejected before any other work", async () => {
    const res = await post(noToken);
    assert.equal(res.code, 422);
    assert.equal(res.payload.fields.turnstile_token, "captcha_required");
    assert.deepEqual([calls.rate.length, calls.submit.length], [0, 0]);
  });
});

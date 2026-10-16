import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parseInquiry } from "../lib/schema";
import {
  normalizeWhatsapp,
  sanitizeLine,
  sanitizeMultiline,
} from "../lib/sanitize";
import { loadEnv } from "../lib/env";

const valid = {
  division: "bbt",
  locale: "en",
  name: "  Ana   Tester ",
  org_type: "corporate",
  organization: "PT Contoh",
  email: "  Ana@Example.COM ",
  whatsapp: "0812-3456-7890",
  service_interest: "web_app",
  message: "We would like a dashboard for our regional team.",
  consent: true,
  t: 9000,
  turnstile_token: "tok",
};

describe("parseInquiry", () => {
  it("accepts a valid body and normalises it", () => {
    const r = parseInquiry(valid);
    assert.ok(r.ok);
    assert.equal(r.data.name, "Ana Tester");
    assert.equal(r.data.email, "ana@example.com");
    assert.equal(r.data.whatsapp, "+6281234567890");
  });

  it("reports one code per field, with required for missing values", () => {
    const r = parseInquiry({});
    assert.ok(!r.ok);
    for (const f of ["division", "name", "email", "message", "org_type"]) {
      assert.ok(f in r.fields, `${f} should be reported`);
    }
    assert.equal(r.fields.name, "required");
    assert.equal(r.fields.consent, "consent_required");
  });

  it("rejects bad enums, email, whatsapp, consent", () => {
    const r = parseInquiry({
      ...valid,
      division: "hax",
      email: "a@b",
      whatsapp: "123",
      consent: false,
      org_type: "x",
    });
    assert.ok(!r.ok);
    assert.equal(r.fields.division, "invalid_division");
    assert.equal(r.fields.email, "invalid_email");
    assert.equal(r.fields.whatsapp, "invalid_whatsapp");
    assert.equal(r.fields.consent, "consent_required");
    assert.equal(r.fields.org_type, "invalid_org_type");
  });

  it("enforces length limits after sanitising", () => {
    assert.equal(
      (parseInquiry({ ...valid, name: "A" }) as any).fields.name,
      "too_short",
    );
    assert.equal(
      (parseInquiry({ ...valid, name: "x".repeat(121) }) as any).fields.name,
      "too_long",
    );
    assert.equal(
      (parseInquiry({ ...valid, message: "short" }) as any).fields.message,
      "too_short",
    );
    assert.equal(
      (parseInquiry({ ...valid, message: "x".repeat(5001) }) as any).fields
        .message,
      "too_long",
    );
    assert.equal(
      (parseInquiry({ ...valid, name: "​​" }) as any).fields.name,
      "required",
    );
  });

  it("rejects link-stuffed messages", () => {
    const spam =
      "buy http://a.co http://b.co http://c.co http://d.co now please";
    assert.equal(
      (parseInquiry({ ...valid, message: spam }) as any).fields.message,
      "too_many_links",
    );
  });

  it("rejects unknown keys, so source_site can never come from the body", () => {
    const r = parseInquiry({ ...valid, source_site: "media" });
    assert.ok(!r.ok);
    assert.equal(r.fields._form, "unexpected_field");
  });

  it("rejects header-injection style emails", () => {
    for (const bad of [
      "a@b.co\r\nBcc: x@y.co",
      "a b@c.co",
      "a@b.co,c@d.co",
      '"a"@b.co',
    ]) {
      const r = parseInquiry({ ...valid, email: bad });
      assert.ok(!r.ok, bad);
    }
  });

  it("never fails on messy tracking fields", () => {
    const r = parseInquiry({
      ...valid,
      utm_source: "x".repeat(500),
      utm_medium: 123,
      referrer: "https://baritobahalap.com/path?token=secret#frag",
    });
    assert.ok(r.ok);
    assert.equal(r.data.utm_source?.length, 100);
    assert.equal(r.data.utm_medium, undefined);
    assert.equal(r.data.referrer, "https://baritobahalap.com/path");
  });

  it("treats blank optional fields as absent", () => {
    const r = parseInquiry({
      ...valid,
      organization: "  ",
      whatsapp: "",
      service_interest: "",
    });
    assert.ok(r.ok);
    assert.equal(r.data.organization, undefined);
    assert.equal(r.data.whatsapp, undefined);
    assert.equal(r.data.service_interest, undefined);
  });
});

describe("sanitize", () => {
  it("strips control and bidi characters, keeps normal text", () => {
    assert.equal(sanitizeLine("Bu\u0000di‮  Santoso"), "Budi Santoso");
    assert.equal(sanitizeMultiline("a\r\n\r\n\r\n\r\nb\u0007"), "a\n\nb");
  });
  it("normalises Indonesian phone formats", () => {
    assert.equal(normalizeWhatsapp("0812 3456 7890"), "+6281234567890");
    assert.equal(normalizeWhatsapp("+62 812-3456-7890"), "+6281234567890");
    assert.equal(normalizeWhatsapp("6281234567890"), "+6281234567890");
    assert.equal(normalizeWhatsapp("0062 812 3456 7890"), "+6281234567890");
  });
});

describe("loadEnv", () => {
  const base = {
    SUPABASE_URL: "https://x.supabase.co",
    SUPABASE_SERVICE_ROLE_KEY: "k",
    TURNSTILE_SECRET_KEY: "s",
    RESEND_API_KEY: "r",
    MAIL_FROM: "BBA <no-reply@notify.example.com>",
    INBOX_TECH: "tech@example.com",
    INBOX_MEDIA: "media@example.com",
    INBOX_INQUIRY: "inquiry@example.com",
    RATE_LIMIT_SALT: "0123456789abcdef",
    ALLOWED_ORIGINS: '{"https://example.com":"corporate"}',
  };
  it("loads a complete config", () =>
    assert.equal(
      loadEnv(base).origins.get("https://example.com"),
      "corporate",
    ));
  it("names missing variables without echoing values", () => {
    assert.throws(
      () => loadEnv({ ...base, RATE_LIMIT_SALT: "" }),
      /Missing env: RATE_LIMIT_SALT/,
    );
  });
  it("refuses a VITE_-prefixed secret", () => {
    assert.throws(
      () => loadEnv({ ...base, VITE_SUPABASE_SERVICE_ROLE_KEY: "oops" }),
      /VITE_/,
    );
  });
  it("rejects http origins except localhost, and unknown sites", () => {
    assert.throws(
      () =>
        loadEnv({ ...base, ALLOWED_ORIGINS: '{"http://example.com":"tech"}' }),
      /https/,
    );
    assert.throws(
      () =>
        loadEnv({
          ...base,
          ALLOWED_ORIGINS: '{"https://example.com":"admin"}',
        }),
      /unknown site/,
    );
    assert.doesNotThrow(() =>
      loadEnv({ ...base, ALLOWED_ORIGINS: '{"http://localhost:5173":"tech"}' }),
    );
  });
});

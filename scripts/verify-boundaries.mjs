#!/usr/bin/env node
// 4.11  Probe the LIVE deployment from the outside, the way an attacker would.
//
//   SUPABASE_URL=https://xxx.supabase.co SUPABASE_ANON_KEY=... \
//   API_URL=https://api.baritobahalap.com/api/inquiry \
//   GOOD_ORIGIN=https://baritobahalap.com BAD_ORIGIN=https://evil.example \
//   node scripts/verify-boundaries.mjs
//
// Exit code 1 if any boundary is open. Sends no real inquiries.
const {
  SUPABASE_URL,
  SUPABASE_ANON_KEY,
  API_URL,
  GOOD_ORIGIN,
  BAD_ORIGIN = "https://evil.example",
} = process.env;

let failures = 0;
const check = (ok, label, detail = "") => {
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${label}${ok ? "" : `   <- ${detail}`}`,
  );
  if (!ok) failures += 1;
};
const text = async (res) =>
  (await res.text()).slice(0, 160).replace(/\s+/g, " ");

if (SUPABASE_URL && SUPABASE_ANON_KEY) {
  console.log(`\n== Supabase Data API as anon (${SUPABASE_URL}) ==`);
  const h = (extra = {}) => ({
    apikey: SUPABASE_ANON_KEY,
    Authorization: `Bearer ${SUPABASE_ANON_KEY}`,
    ...extra,
  });

  // A response is "closed" when it is an error, or a 200 with an empty array.
  const closedGet = async (path, profile) => {
    const res = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
      headers: h(profile ? { "Accept-Profile": profile } : {}),
    });
    const body = await text(res);
    return { closed: !res.ok || body === "[]", status: res.status, body };
  };

  for (const [path, profile] of [
    ["inquiries?select=*", "intake"],
    ["inquiry_events?select=*", "intake"],
    ["rate_limits?select=*", "internal"],
    ["inquiry_counters?select=*", "internal"],
    ["inquiries?select=*", "internal"],
  ]) {
    const r = await closedGet(path, profile);
    check(
      r.closed,
      `anon cannot read ${profile}.${path.split("?")[0]}`,
      `HTTP ${r.status} ${r.body}`,
    );
  }

  const internalSchema = await fetch(`${SUPABASE_URL}/rest/v1/rate_limits`, {
    headers: h({ "Accept-Profile": "internal" }),
  });
  check(
    internalSchema.status === 406,
    "`internal` is not an exposed schema (expect 406)",
    `HTTP ${internalSchema.status}`,
  );

  for (const fn of ["submit_inquiry", "check_rate_limit"]) {
    const res = await fetch(`${SUPABASE_URL}/rest/v1/rpc/${fn}`, {
      method: "POST",
      headers: h({
        "Content-Type": "application/json",
        "Content-Profile": "intake",
      }),
      body: JSON.stringify({}),
    });
    check(
      !res.ok,
      `anon cannot call intake.${fn}`,
      `HTTP ${res.status} ${await text(res)}`,
    );
  }
  const insert = await fetch(`${SUPABASE_URL}/rest/v1/inquiries`, {
    method: "POST",
    headers: h({
      "Content-Type": "application/json",
      "Content-Profile": "intake",
    }),
    body: JSON.stringify({ name: "x" }),
  });
  check(
    !insert.ok,
    "anon cannot INSERT into intake.inquiries",
    `HTTP ${insert.status}`,
  );

  const pub = await fetch(
    `${SUPABASE_URL}/rest/v1/published_portfolio?select=*`,
    { headers: h() },
  );
  const rows = pub.ok ? await pub.json() : [];
  check(pub.ok, "anon can read published_portfolio", `HTTP ${pub.status}`);
  check(
    rows.every(
      (r) =>
        !("internal_notes" in r) && !("status" in r) && !("created_by" in r),
    ),
    "published_portfolio exposes no internal columns",
    JSON.stringify(Object.keys(rows[0] ?? {})),
  );
  const notes = await fetch(
    `${SUPABASE_URL}/rest/v1/portfolio_items?select=internal_notes`,
    { headers: h() },
  );
  check(
    !notes.ok,
    "anon cannot read portfolio_items.internal_notes",
    `HTTP ${notes.status}`,
  );
} else {
  console.log(
    "\n(skipping Supabase checks: set SUPABASE_URL and SUPABASE_ANON_KEY)",
  );
}

if (API_URL && GOOD_ORIGIN) {
  console.log(`\n== /api/inquiry (${API_URL}) ==`);
  const send = (init) => fetch(API_URL, init);
  const json = (origin, body, extra = {}) => ({
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(origin ? { Origin: origin } : {}),
      ...extra,
    },
    body: JSON.stringify(body),
  });

  let r = await send({
    method: "OPTIONS",
    headers: { Origin: BAD_ORIGIN, "Access-Control-Request-Method": "POST" },
  });
  check(
    r.status === 403 && !r.headers.get("access-control-allow-origin"),
    "preflight from a foreign origin is refused",
    `HTTP ${r.status}`,
  );

  r = await send({
    method: "OPTIONS",
    headers: { Origin: GOOD_ORIGIN, "Access-Control-Request-Method": "POST" },
  });
  check(
    r.status === 204 &&
      r.headers.get("access-control-allow-origin") === GOOD_ORIGIN,
    "preflight from an allowed origin echoes that origin only",
    `HTTP ${r.status}`,
  );

  r = await send(json(BAD_ORIGIN, {}));
  check(
    r.status === 403,
    "POST from a foreign origin is refused",
    `HTTP ${r.status}`,
  );

  r = await send(json(undefined, {}));
  check(r.status === 403, "POST with no Origin is refused", `HTTP ${r.status}`);

  r = await send({ method: "GET", headers: { Origin: GOOD_ORIGIN } });
  check(r.status === 405, "GET is refused", `HTTP ${r.status}`);

  r = await send({
    method: "POST",
    headers: { Origin: GOOD_ORIGIN, "Content-Type": "text/plain" },
    body: "x",
  });
  check(r.status === 415, "non-JSON body is refused", `HTTP ${r.status}`);

  r = await send(
    json(
      GOOD_ORIGIN,
      { pad: "x".repeat(20_000) },
      { "Content-Length": "20100" },
    ),
  );
  check(
    [413, 422].includes(r.status),
    "oversized body is refused",
    `HTTP ${r.status}`,
  );

  r = await send(json(GOOD_ORIGIN, {}));
  const empty = await r.json().catch(() => ({}));
  check(
    r.status === 422 && empty.error === "validation",
    "empty body gives 422 validation, not a 500",
    `HTTP ${r.status} ${JSON.stringify(empty)}`,
  );

  r = await send(
    json(GOOD_ORIGIN, {
      division: "bbt",
      locale: "en",
      name: "Boundary Check",
      org_type: "individual",
      email: "boundary@example.com",
      message: "Automated boundary check, no captcha token.",
      consent: true,
      t: 9000,
      turnstile_token: "invalid-token",
    }),
  );
  const bad = await r.json().catch(() => ({}));
  check(
    r.status === 400 && bad.error === "captcha_failed",
    "a request without a valid Turnstile token is refused",
    `HTTP ${r.status} ${JSON.stringify(bad)}`,
  );
  check(
    !JSON.stringify(bad).match(/supabase|stack|at \w+ \(/i),
    "errors leak no internals",
  );
} else {
  console.log("\n(skipping API checks: set API_URL and GOOD_ORIGIN)");
}

console.log(
  failures === 0
    ? "\nAll boundaries closed."
    : `\n${failures} boundary check(s) FAILED.`,
);
process.exit(failures === 0 ? 0 : 1);

import type { VercelRequest, VercelResponse } from "@vercel/node";
import { ConfigError, loadEnv } from "../lib/env";
import { createHandler, type ReqLike, type ResLike } from "../lib/handler";
import { createRealDeps } from "../lib/deps";

let handler: ((req: ReqLike, res: ResLike) => Promise<void>) | undefined;

export default async function inquiry(
  req: VercelRequest,
  res: VercelResponse,
): Promise<void> {
  try {
    handler ??= createHandler(createRealDeps(loadEnv(process.env)));
  } catch (error) {
    // Names of missing/invalid settings only, never values.
    console.error(
      JSON.stringify({
        evt: "config_error",
        message: error instanceof ConfigError ? error.message : "unknown",
      }),
    );
    res.status(500).json({ ok: false, error: "server_error" });
    return;
  }
  await handler(req, res);
}

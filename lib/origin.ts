export type SourceSite = "corporate" | "tech" | "media";
export type OriginMap = ReadonlyMap<string, SourceSite>;

export class ConfigError extends Error {}

const SITES: ReadonlySet<string> = new Set(["corporate", "tech", "media"]);
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1"]);

/**
 * ALLOWED_ORIGINS is a JSON object: { "<origin>": "<site>" }, for example
 *   {"https://baritobahalap.com":"corporate",
 *    "https://tech.baritobahalap.com":"tech",
 *    "https://media.baritobahalap.com":"media"}
 * The mapped site becomes inquiries.source_site, so it is derived from the
 * verified Origin header and can never be chosen by the request body.
 */
export function parseOriginMap(raw: string | undefined): OriginMap {
  if (!raw) throw new ConfigError("ALLOWED_ORIGINS is not set");

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new ConfigError("ALLOWED_ORIGINS must be valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new ConfigError("ALLOWED_ORIGINS must be a JSON object");
  }

  const map = new Map<string, SourceSite>();
  for (const [key, site] of Object.entries(parsed)) {
    let url: URL;
    try {
      url = new URL(key);
    } catch {
      throw new ConfigError(`ALLOWED_ORIGINS has an invalid origin: ${key}`);
    }
    const local = LOCAL_HOSTS.has(url.hostname);
    if (url.protocol !== "https:" && !(local && url.protocol === "http:")) {
      throw new ConfigError(
        `ALLOWED_ORIGINS origin must be https (http only for localhost): ${key}`,
      );
    }
    if (typeof site !== "string" || !SITES.has(site)) {
      throw new ConfigError(`ALLOWED_ORIGINS has an unknown site for ${key}`);
    }
    map.set(url.origin, site as SourceSite);
  }
  if (map.size === 0) throw new ConfigError("ALLOWED_ORIGINS is empty");
  return map;
}

export interface OriginMatch {
  origin: string;
  site: SourceSite;
  hostname: string;
}

export function resolveOrigin(
  header: string | undefined,
  map: OriginMap,
): OriginMatch | null {
  if (!header) return null;
  const site = map.get(header);
  if (!site) return null;
  return { origin: header, site, hostname: new URL(header).hostname };
}

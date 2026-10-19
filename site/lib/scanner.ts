import { lookup } from "node:dns/promises";
import { request as httpRequest } from "node:http";
import type { IncomingMessage } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { parse } from "parse5";

export type Finding = {
  id: string;
  title: string;
  detail: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "pass" | "issue" | "info";
  resource?: string;
  evidence?: string;
  recommendation?: string;
};
export type ScannedAsset = { url: string; kind: "script" | "stylesheet" | "source map"; status: number | null };
export type ScanReport = { id: string; targetUrl: string; scannedAt: string; score: number; checks: Finding[]; assets: ScannedAsset[] };

const MAX_BODY_BYTES = 1_000_000;
const MAX_ASSETS = 10;
const MAX_REDIRECTS = 4;
const REQUEST_TIMEOUT_MS = 6000;
const MAX_CRAWL_PAGES = 20;
const MAX_CRAWL_DURATION_MS = 30_000;
const MAX_SITE_ASSETS = 40;
const MAX_DISCOVERED_PAGES = 200;

function isPrivateAddress(address: string) {
  if (isIP(address) === 4) {
    const [a, b, c] = address.split(".").map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)) || (b === 88 && c === 99))) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) || (a === 203 && b === 0 && c === 113);
  }
  if (isIP(address) === 6) {
    const value = address.toLowerCase();
    const secondBlock = value.startsWith("2001:") ? Number.parseInt(value.split(":")[1] || "0", 16) : 0;
    return (!value.startsWith("2") && !value.startsWith("3")) ||
      (value.startsWith("2001:") && secondBlock <= 0x01ff) || value.startsWith("2002:") || value.startsWith("3fff:");
  }
  return true;
}

async function validateTarget(target: URL, allowedHost: string) {
  if (target.protocol !== "https:" && target.protocol !== "http:") throw new Error("Only HTTP and HTTPS website URLs are supported.");
  if (target.username || target.password) throw new Error("URLs containing credentials are not allowed.");
  if (target.port && target.port !== "80" && target.port !== "443") throw new Error("Only standard web ports (80 and 443) can be scanned.");
  const hostname = target.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (hostname !== allowedHost || hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".local")) {
    throw new Error("Redirects must stay on the original public website.");
  }
  const family = isIP(hostname);
  const addresses = family ? [{ address: hostname, family }] : await lookup(hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(({ address }) => isPrivateAddress(address))) {
    throw new Error("This website resolves to a private or reserved network address and cannot be scanned.");
  }
  return addresses;
}

async function readLimited(response: IncomingMessage, maxBytes: number) {
  const chunks: Uint8Array[] = [];
  let size = 0;
  for await (const chunk of response) {
    const value = new Uint8Array(chunk);
    size += value.byteLength;
    if (size > maxBytes) {
      response.destroy();
      throw new Error("The website response is larger than the scan limit.");
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { merged.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder().decode(merged);
}

async function fetchPublic(target: URL, allowedHost: string, maxBytes = MAX_BODY_BYTES, timeoutMs = REQUEST_TIMEOUT_MS) {
  let current = target;
  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects += 1) {
    const addresses = await validateTarget(current, allowedHost);
    const request = current.protocol === "https:" ? httpsRequest : httpRequest;
    const response = await new Promise<IncomingMessage>((resolve, reject) => {
      const outgoing = request(current, {
        signal: AbortSignal.timeout(Math.max(1, Math.min(REQUEST_TIMEOUT_MS, timeoutMs))),
        headers: { "User-Agent": "PerimeterSecurityScanner/1.0 (+read-only public website checks)", Accept: "text/html,application/javascript,text/css,application/json;q=0.9,*/*;q=0.2" },
        lookup(_hostname, options, callback) {
          if (options.all) callback(null, addresses);
          else {
            const address = addresses.find((entry) => !options.family || entry.family === options.family) ?? addresses[0];
            callback(null, address.address, address.family);
          }
        },
      }, resolve);
      outgoing.once("error", reject);
      outgoing.end();
    });
    const headers = new Headers();
    for (const [name, value] of Object.entries(response.headers)) {
      if (typeof value === "string") headers.set(name, value);
      else if (Array.isArray(value)) headers.set(name, value.join(", "));
    }
    if ([301, 302, 303, 307, 308].includes(response.statusCode ?? 0)) {
      const location = headers.get("location");
      response.on("error", () => undefined);
      response.destroy();
      if (!location || redirects === MAX_REDIRECTS) throw new Error("The website has too many redirects to scan safely.");
      current = new URL(location, current);
      continue;
    }
    const body = await readLimited(response, maxBytes);
    return { response: { status: response.statusCode ?? 0, headers, ok: response.statusCode !== undefined && response.statusCode >= 200 && response.statusCode < 300 }, body, finalUrl: current };
  }
  throw new Error("The website could not be reached safely.");
}

function addCheck(checks: Finding[], id: string, title: string, detail: string, severity: Finding["severity"], status: Finding["status"], resource?: string, evidence?: string, recommendation?: string) {
  checks.push({ id, title, detail, severity, status, ...(resource ? { resource } : {}), ...(evidence ? { evidence } : {}), ...(recommendation ? { recommendation } : {}) });
}

function parseDirectives(value: string) {
  return new Map(value.split(";").map((part) => part.trim()).filter(Boolean).map((part) => {
    const [name, ...tokens] = part.toLowerCase().split(/\s+/);
    return [name, tokens] as const;
  }));
}

export function assessSecurityHeaders(headers: Pick<Headers, "get">, isHttps: boolean): Finding[] {
  const checks: Finding[] = [];
  const csp = headers.get("content-security-policy")?.trim() ?? "";
  const directives = parseDirectives(csp);
  const scriptSources = directives.get("script-src") ?? directives.get("default-src") ?? [];
  const styleSources = directives.get("style-src") ?? directives.get("default-src") ?? [];
  const nonceOrHash = (token: string) => /^'(?:nonce-.+|sha256-.+|sha384-.+|sha512-.+)'$/.test(token);
  const cspWeaknesses = [
    ...(!directives.has("script-src") && !directives.has("default-src") ? ["missing script-src/default-src directive"] : []),
    ...(scriptSources.includes("*") || styleSources.includes("*") ? ["wildcard script/style source"] : []),
    ...(scriptSources.includes("'unsafe-eval'") ? ["unsafe-eval in script policy"] : []),
    ...(scriptSources.includes("'unsafe-inline'") && !scriptSources.some(nonceOrHash) ? ["unsafe-inline without a nonce or hash"] : []),
    ...(styleSources.includes("'unsafe-inline'") && !styleSources.some(nonceOrHash) ? ["unsafe-inline styles without a nonce or hash"] : []),
  ];
  const cspStatus = !csp ? "issue" : cspWeaknesses.length ? "issue" : "pass";
  addCheck(checks, "csp", "Content Security Policy", !csp ? "No enforced Content-Security-Policy header was found." : cspWeaknesses.length ? `The policy contains ${cspWeaknesses.join(" and ")}.` : "The enforced policy was present and no wildcard or unsafe script directives were found.", "medium", cspStatus, "Content-Security-Policy", csp || "Header absent", cspStatus === "issue" ? "Define explicit trusted sources; avoid wildcards and unsafe script directives." : undefined);

  const hsts = headers.get("strict-transport-security")?.trim() ?? "";
  const maxAge = Number(/(?:^|;)\s*max-age\s*=\s*(\d+)/i.exec(hsts)?.[1] ?? 0);
  const hstsValid = isHttps && maxAge > 0;
  addCheck(checks, "hsts", "Strict Transport Security", hstsValid ? `HSTS is enabled with max-age=${maxAge}${/includeSubDomains/i.test(hsts) ? " and includeSubDomains" : ""}.` : !isHttps ? "The page was reached over HTTP, so HSTS cannot be confirmed." : hsts ? "The HSTS header is malformed or has max-age=0." : "No Strict-Transport-Security header was found.", "medium", hstsValid ? "pass" : "issue", "Strict-Transport-Security", hsts || "Header absent", "Serve HTTPS and use a positive HSTS max-age.");

  const nosniff = headers.get("x-content-type-options")?.trim().toLowerCase() === "nosniff";
  addCheck(checks, "nosniff", "MIME type protection", nosniff ? "X-Content-Type-Options is set to nosniff." : "X-Content-Type-Options: nosniff was not found.", "low", nosniff ? "pass" : "issue", "X-Content-Type-Options", headers.get("x-content-type-options") ?? "Header absent", "Set X-Content-Type-Options: nosniff.");

  const xFrame = headers.get("x-frame-options")?.trim().toLowerCase() ?? "";
  const frameAncestors = directives.get("frame-ancestors") ?? [];
  const cspFrameProtected = frameAncestors.length > 0 && !frameAncestors.includes("*") &&
    (!frameAncestors.includes("'none'") || frameAncestors.length === 1);
  const frameProtected = ["deny", "sameorigin"].includes(xFrame) || cspFrameProtected;
  addCheck(checks, "framing", "Clickjacking protection", frameProtected ? "A restrictive X-Frame-Options or CSP frame-ancestors directive was found." : "No valid X-Frame-Options or restrictive CSP frame-ancestors directive was found.", "medium", frameProtected ? "pass" : "issue", "X-Frame-Options / Content-Security-Policy", [xFrame && `X-Frame-Options: ${xFrame}`, frameAncestors.length && `frame-ancestors ${frameAncestors.join(" ")}`].filter(Boolean).join("; ") || "No frame restriction", "Set X-Frame-Options to DENY or SAMEORIGIN, or use a restrictive frame-ancestors directive.");

  const referrerPolicy = headers.get("referrer-policy")?.trim().toLowerCase() ?? "";
  const strongReferrerPolicies = new Set(["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"]);
  const referrerValues = referrerPolicy.split(",").map((value) => value.trim()).filter(Boolean);
  const acceptedReferrer = referrerValues.find((value) => strongReferrerPolicies.has(value));
  const referrerValid = Boolean(acceptedReferrer);
  addCheck(checks, "referrer", "Referrer policy", referrerValid ? `A strict policy (${acceptedReferrer}) is present in the Referrer-Policy value.` : referrerPolicy ? `No policy in “${referrerPolicy}” matches the scanner's strict baseline.` : "No Referrer-Policy header was found.", "low", referrerValid ? "pass" : "issue", "Referrer-Policy", referrerPolicy || "Header absent", "Use strict-origin-when-cross-origin or a more restrictive policy.");

  const permissionsPolicy = headers.get("permissions-policy")?.trim() ?? "";
  const permissionParts = permissionsPolicy ? permissionsPolicy.split(",").map((part) => part.trim()) : [];
  const permissionDirectives = permissionParts.map((part) => /^([a-z][a-z0-9-]*)\s*=\s*\(([^()]*)\)$/i.exec(part));
  const permissionsValid = permissionDirectives.length > 0 && permissionDirectives.every((match) => match !== null && match[2].trim() !== "*");
  addCheck(checks, "permissions", "Permissions Policy", permissionsValid ? `${permissionDirectives.length} valid feature restriction${permissionDirectives.length === 1 ? "" : "s"} found.` : "Permissions-Policy is missing or contains malformed or unrestricted directives.", "low", permissionsValid ? "pass" : "issue", "Permissions-Policy", permissionsPolicy || "Header absent", "Explicitly restrict browser features the site does not need.");

  const serverHeader = headers.get("server");
  addCheck(checks, "server-header", "Server version disclosure", serverHeader ? `The response identifies its server as “${serverHeader.slice(0, 100)}”. Consider minimizing version details.` : "No Server header was exposed.", "info", serverHeader ? "info" : "pass", "Server", serverHeader ?? "Header absent");
  const poweredBy = headers.get("x-powered-by");
  addCheck(checks, "powered-by", "Technology disclosure", poweredBy ? `X-Powered-By exposes “${poweredBy.slice(0, 100)}”. Consider removing the header.` : "No X-Powered-By header was exposed.", "low", poweredBy ? "issue" : "pass", "X-Powered-By", poweredBy ?? "Header absent", "Remove X-Powered-By from public responses.");
  return checks;
}

type HtmlNode = { tagName?: string; attrs?: { name: string; value: string }[]; childNodes?: HtmlNode[] };
type AssetTarget = { url: string; kind: "script" | "stylesheet" };

export function inspectHtmlResources(html: string, pageUrl: string) {
  const page = new URL(pageUrl);
  const mixedContentUrls = new Set<string>();
  const thirdPartyWithoutIntegrity = new Set<string>();
  const assetTargets: AssetTarget[] = [];
  const document = parse(html) as unknown as HtmlNode;
  const inspectReference = (rawUrl: string) => {
    try {
      const resolved = new URL(rawUrl, page);
      if (page.protocol === "https:" && resolved.protocol === "http:") mixedContentUrls.add(resolved.href);
      return resolved;
    } catch { return null; }
  };
  const walk = (node: HtmlNode) => {
    if (node.tagName) {
      const attributes = new Map((node.attrs ?? []).map(({ name, value }) => [name.toLowerCase(), value]));
      const tag = node.tagName.toLowerCase();
      const rel = (attributes.get("rel") ?? "").toLowerCase().split(/\s+/);
      const src = attributes.get("src");
      const href = attributes.get("href");
      const resourceUrls: string[] = [];
      if (["script", "img", "iframe", "audio", "video", "source", "track", "embed"].includes(tag) && src) resourceUrls.push(src);
      if (tag === "video" && attributes.has("poster")) resourceUrls.push(attributes.get("poster") as string);
      if (tag === "object" && attributes.has("data")) resourceUrls.push(attributes.get("data") as string);
      if (tag === "link" && href) resourceUrls.push(href);
      if (attributes.has("srcset")) resourceUrls.push(...(attributes.get("srcset") as string).match(/https?:\/\/[^\s,]+/gi) ?? []);
      if (attributes.has("style")) resourceUrls.push(...[...(attributes.get("style") as string).matchAll(/url\(\s*["']?(https?:\/\/[^"')\s]+)/gi)].map((match) => match[1]));
      for (const resourceUrl of resourceUrls) inspectReference(resourceUrl);

      const scriptLike = tag === "script" && src || tag === "link" && (rel.includes("modulepreload") || rel.includes("preload") && attributes.get("as") === "script");
      const stylesheetLike = tag === "link" && rel.includes("stylesheet");
      const rawAssetUrl = tag === "script" ? src : href;
      const assetKind = scriptLike ? "script" : stylesheetLike ? "stylesheet" : null;
      if (rawAssetUrl && assetKind) {
        const resolved = inspectReference(rawAssetUrl);
        if (resolved && resolved.origin !== page.origin && !attributes.has("integrity")) thirdPartyWithoutIntegrity.add(resolved.href);
        if (resolved && resolved.origin === page.origin && assetTargets.length < MAX_ASSETS) assetTargets.push({ url: resolved.href, kind: assetKind });
      }
    }
    for (const child of node.childNodes ?? []) walk(child);
  };
  walk(document);
  return { mixedContentUrls: [...mixedContentUrls], thirdPartyWithoutIntegrity: [...thirdPartyWithoutIntegrity], assetTargets };
}

export function extractSameOriginLinks(html: string, pageUrl: string, siteOrigin = new URL(pageUrl).origin) {
  const base = new URL(pageUrl);
  const allowedOrigin = new URL(siteOrigin).origin;
  const links = new Set<string>();
  const document = parse(html) as unknown as HtmlNode;
  const walk = (node: HtmlNode) => {
    if (node.tagName === "a" || node.tagName === "area") {
      const attributes = new Map((node.attrs ?? []).map((attribute) => [attribute.name.toLowerCase(), attribute.value]));
      const href = attributes.get("href");
      if (href) {
        try {
          const target = new URL(href, base);
          target.hash = "";
          const isStaticFile = /\.(?:css|js|mjs|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|pdf|zip|xml|json|map)$/i.test(target.pathname);
          const isStateChangingRoute = /(?:^|\/)(?:logout|log-out|signout|sign-out|delete|remove|unsubscribe|checkout|purchase|payment|reset-password|verify|confirm|activate)(?:\/|$)/i.test(target.pathname);
          const nofollow = (attributes.get("rel") ?? "").toLowerCase().split(/\s+/).includes("nofollow");
          if (target.origin === allowedOrigin && !isStaticFile && !isStateChangingRoute && !nofollow) {
            links.add(target.href);
          }
        } catch { /* Ignore malformed links. */ }
      }
    }
    for (const child of node.childNodes ?? []) walk(child);
  };
  walk(document);
  return [...links];
}

export type RobotsRule = { allow: boolean; path: string };

export function parseRobotsRules(body: string, userAgent = "PerimeterSecurityScanner"): RobotsRule[] {
  const matchingRules: RobotsRule[] = [];
  let agents: string[] = [];
  let groupRules: RobotsRule[] = [];
  let hasDirectives = false;
  const flush = () => {
    if (agents.some((agent) => agent === "*" || userAgent.toLowerCase().includes(agent))) matchingRules.push(...groupRules);
    agents = [];
    groupRules = [];
    hasDirectives = false;
  };
  for (const rawLine of body.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, "").trim();
    if (!line) continue;
    const separator = line.indexOf(":");
    if (separator < 0) continue;
    const name = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (name === "user-agent") {
      if (hasDirectives) flush();
      agents.push(value.toLowerCase());
      continue;
    }
    if ((name === "allow" || name === "disallow") && agents.length > 0) {
      hasDirectives = true;
      if (value) groupRules.push({ allow: name === "allow", path: value });
    }
  }
  flush();
  return matchingRules;
}

export function isAllowedByRobots(url: URL, rules: RobotsRule[]) {
  const target = `${url.pathname}${url.search}`;
  let best: { allow: boolean; specificity: number } | null = null;
  for (const rule of rules) {
    const expression = rule.path.endsWith("$") ? rule.path.slice(0, -1) : rule.path;
    const pattern = `^${expression.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replaceAll("\\*", ".*")}${rule.path.endsWith("$") ? "$" : ""}`;
    if (!new RegExp(pattern).test(target)) continue;
    const specificity = rule.path.replace(/[\*$]/g, "").length;
    if (!best || specificity > best.specificity || specificity === best.specificity && rule.allow) best = { allow: rule.allow, specificity };
  }
  return best?.allow ?? true;
}

function isValidSourceMapObject(value: unknown, depth = 0): boolean {
  if (!value || typeof value !== "object" || depth > 8) return false;
  const map = value as { version?: unknown; sources?: unknown; names?: unknown; mappings?: unknown; sections?: unknown; sourcesContent?: unknown };
  if (map.version !== 3) return false;
  if (Array.isArray(map.sections)) {
    return map.sections.length > 0 && map.sections.every((section) => {
      if (!section || typeof section !== "object") return false;
      const item = section as { offset?: { line?: unknown; column?: unknown }; map?: unknown };
      return typeof item.offset?.line === "number" && item.offset.line >= 0 && typeof item.offset.column === "number" && item.offset.column >= 0 && isValidSourceMapObject(item.map, depth + 1);
    });
  }
  return Array.isArray(map.sources) && map.sources.every((source) => typeof source === "string") &&
    Array.isArray(map.names) && map.names.every((name) => typeof name === "string") &&
    typeof map.mappings === "string" && /^[A-Za-z0-9+/;,]*$/.test(map.mappings) &&
    (!map.sourcesContent || Array.isArray(map.sourcesContent) && map.sourcesContent.length === map.sources.length && map.sourcesContent.every((content) => content === null || typeof content === "string"));
}

export function isValidSourceMap(body: string) {
  try { return isValidSourceMapObject(JSON.parse(body)); }
  catch { return false; }
}

type PageInspection = { url: URL; checks: Finding[]; assets: ScannedAsset[]; links: string[] };

async function inspectPage(target: URL, allowedHost: string, origin: string, deadline: number, assetBudget: number, prefetched?: Awaited<ReturnType<typeof fetchPublic>>): Promise<PageInspection> {
  const remainingMs = deadline - Date.now();
  if (remainingMs <= 0) throw new Error("The crawl time limit was reached.");
  const { response, body, finalUrl } = prefetched ?? await fetchPublic(target, allowedHost, MAX_BODY_BYTES, remainingMs);
  if (finalUrl.origin !== origin) throw new Error("Crawl redirects must remain on the original origin.");
  const checks: Finding[] = [];
  const assets: ScannedAsset[] = [];
  if (!response.ok) {
    addCheck(checks, "page-response", "Page response", `The discovered page returned HTTP ${response.status}; its security headers could not be assessed.`, "info", "info", undefined, `HTTP ${response.status}`);
    return { url: finalUrl, checks, assets, links: [] };
  }
  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.includes("text/html") && !contentType.includes("application/xhtml+xml")) {
    addCheck(checks, "page-response", "Page response", "The discovered URL did not return HTML, so page checks were skipped.", "info", "info", undefined, contentType || "Content-Type absent");
    return { url: finalUrl, checks, assets, links: [] };
  }

  const secureTransport = finalUrl.protocol === "https:";
  addCheck(checks, "http-status", "HTTP response", `The page returned HTTP ${response.status}.`, "info", "pass", undefined, `${finalUrl.pathname}: HTTP ${response.status}; ${contentType}`);
  addCheck(checks, "https", "HTTPS transport", secureTransport ? "The page was reached over HTTPS." : "The page is served over HTTP. Use HTTPS to protect visitors and session data.", "high", secureTransport ? "pass" : "issue", finalUrl.origin, `${finalUrl.pathname}: ${finalUrl.protocol}`, "Serve the site over HTTPS and redirect HTTP requests.");
  checks.push(...assessSecurityHeaders(response.headers, secureTransport));
  const inspection = inspectHtmlResources(body, finalUrl.href);
  addCheck(checks, "mixed-content", "Mixed-content references", inspection.mixedContentUrls.length ? `${inspection.mixedContentUrls.length} HTTP resource reference${inspection.mixedContentUrls.length === 1 ? " was" : "s were"} found in parsed HTML elements.` : "No HTTP resource URLs were found in parsed HTML resource attributes.", "high", inspection.mixedContentUrls.length ? "issue" : "pass", undefined, `${finalUrl.pathname}: ${inspection.mixedContentUrls.slice(0, 3).join(", ") || "No mixed-content references"}`, "Update referenced resources to HTTPS or remove them.");
  addCheck(checks, "sri", "Third-party resource integrity", inspection.thirdPartyWithoutIntegrity.length ? `${inspection.thirdPartyWithoutIntegrity.length} cross-origin script or stylesheet${inspection.thirdPartyWithoutIntegrity.length === 1 ? " is" : "s are"} missing Subresource Integrity.` : "No cross-origin script or stylesheet without integrity was found.", "medium", inspection.thirdPartyWithoutIntegrity.length ? "issue" : "pass", "script/link integrity", `${finalUrl.pathname}: ${inspection.thirdPartyWithoutIntegrity.slice(0, 3).join(", ") || "No unpinned third-party resources"}`, "Use Subresource Integrity for static cross-origin scripts and stylesheets where supported.");

  let inspectedFiles = 0;
  let exposedMaps = 0;
  let assetRequests = 0;
  const checkedMaps = new Set<string>();
  for (const asset of inspection.assetTargets.slice(0, Math.min(assetBudget, MAX_ASSETS))) {
    if (Date.now() >= deadline || assetRequests >= assetBudget) break;
    assetRequests += 1;
    try {
      const assetUrl = new URL(asset.url);
      const result = await fetchPublic(assetUrl, allowedHost, 300_000, deadline - Date.now());
      if (result.finalUrl.origin !== origin) throw new Error("Asset redirects must remain on the original origin.");
      assets.push({ url: assetUrl.href, kind: asset.kind, status: result.response.status });
      inspectedFiles += 1;
      if (asset.kind !== "script") continue;
      const mapReference = result.body.match(/[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)/);
      if (!mapReference || checkedMaps.size >= 4 || assetRequests >= assetBudget) continue;
      const mapUrl = new URL(mapReference[1], result.finalUrl);
      if (mapUrl.origin !== origin || checkedMaps.has(mapUrl.href)) continue;
      checkedMaps.add(mapUrl.href);
      assetRequests += 1;
      try {
        const map = await fetchPublic(mapUrl, allowedHost, 300_000, deadline - Date.now());
        if (map.finalUrl.origin !== origin) throw new Error("Source-map redirects must remain on the original origin.");
        assets.push({ url: mapUrl.href, kind: "source map", status: map.response.status });
        if (map.response.ok && isValidSourceMap(map.body)) exposedMaps += 1;
      } catch { assets.push({ url: mapUrl.href, kind: "source map", status: null }); }
    } catch { assets.push({ url: asset.url, kind: asset.kind, status: null }); }
  }
  addCheck(checks, "source-maps", "Public source maps", exposedMaps ? `${exposedMaps} valid version 3 source map${exposedMaps === 1 ? " is" : "s are"} publicly accessible.` : checkedMaps.size ? "Referenced source-map URLs were checked, but no valid source-map document was confirmed." : "No same-origin source-map reference was found in inspected scripts.", "medium", exposedMaps ? "issue" : "pass", "version 3 source map JSON", `${finalUrl.pathname}: ${exposedMaps ? `${exposedMaps} valid public map${exposedMaps === 1 ? "" : "s"}` : "No valid public source map"}`, "Avoid publishing source maps with original sources to public production paths.");
  addCheck(checks, "asset-coverage", "Same-origin assets inspected", inspectedFiles ? `${inspectedFiles} same-origin script or stylesheet${inspectedFiles === 1 ? " was" : "s were"} fetched within the scan limits.` : "No same-origin script or stylesheet was discovered in the page markup.", "info", "info", undefined, `${finalUrl.pathname}: ${inspection.assetTargets.length} referenced; ${inspectedFiles} fetched`);
  return { url: finalUrl, checks, assets, links: extractSameOriginLinks(body, finalUrl.href, origin) };
}

export function aggregatePageChecks(pages: PageInspection[]) {
  const grouped = new Map<string, Finding[]>();
  for (const page of pages) {
    const path = `${page.url.pathname}${page.url.search}`;
    for (const check of page.checks) {
      const finding = { ...check, evidence: `${path}: ${check.evidence ?? check.detail}` };
      const group = grouped.get(check.id) ?? [];
      group.push(finding);
      grouped.set(check.id, group);
    }
  }
  return [...grouped.entries()].map(([id, findings]) => {
    const issueFindings = findings.filter((finding) => finding.status === "issue");
    const worstStatus = issueFindings.length ? "issue" : findings.some((finding) => finding.status === "info") ? "info" : "pass";
    const severityOrder: Finding["severity"][] = ["info", "low", "medium", "high", "critical"];
    const severity = findings.reduce((highest, finding) => severityOrder.indexOf(finding.severity) > severityOrder.indexOf(highest) ? finding.severity : highest, "info" as Finding["severity"]);
    const uniqueDetails = [...new Set((issueFindings.length ? issueFindings : findings).map((finding) => finding.detail))];
    const affectedPaths = [...new Set((issueFindings.length ? issueFindings : findings).map((finding) => finding.evidence?.split(": ")[0] ?? "/"))];
    return {
      ...findings[0],
      status: worstStatus,
      severity,
      detail: issueFindings.length ? `${issueFindings.length} of ${findings.length} inspected pages flagged this check. ${uniqueDetails.slice(0, 2).join(" ")}` : uniqueDetails[0],
      evidence: (issueFindings.length ? issueFindings : findings).slice(0, 8).map((finding) => finding.evidence).join("; "),
      resource: id === "https" ? `${affectedPaths.length} page${affectedPaths.length === 1 ? "" : "s"} checked` : findings[0].resource,
    } satisfies Finding;
  });
}

export async function scanWebsite(input: string): Promise<ScanReport> {
  let requested: URL;
  try { requested = new URL(input); } catch { throw new Error("Enter a valid website URL, including its domain."); }
  requested.hash = "";
  if (!requested.hostname) throw new Error("Enter a valid website URL.");
  const allowedHost = requested.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const deadline = Date.now() + MAX_CRAWL_DURATION_MS;
  const root = await fetchPublic(requested, allowedHost, MAX_BODY_BYTES, MAX_CRAWL_DURATION_MS);
  if (!root.response.ok) throw new Error(`The website returned HTTP ${root.response.status}; security checks were not scored for an unsuccessful response.`);
  const rootContentType = root.response.headers.get("content-type")?.toLowerCase() ?? "";
  if (!rootContentType.includes("text/html") && !rootContentType.includes("application/xhtml+xml")) {
    throw new Error("The URL did not return an HTML document, so page security checks could not be validated.");
  }
  const origin = root.finalUrl.origin;
  const robotsUrl = new URL("/robots.txt", origin);
  let robotsRules: RobotsRule[] = [];
  let robotsStatus: "available" | "not-found" | "unavailable" = "unavailable";
  try {
    if (Date.now() < deadline) {
      const robots = await fetchPublic(robotsUrl, allowedHost, 100_000, Math.min(2500, deadline - Date.now()));
      if (robots.response.ok) {
        robotsRules = parseRobotsRules(robots.body);
        robotsStatus = "available";
      } else if (robots.response.status === 404 || robots.response.status === 410) {
        robotsStatus = "not-found";
      }
    }
  } catch { robotsRules = []; }
  if (!isAllowedByRobots(root.finalUrl, robotsRules)) throw new Error("The site's robots.txt disallows scanning the requested path.");
  if (Date.now() >= deadline) throw new Error("The crawl time limit was reached before the first page could be inspected.");

  const queue: URL[] = [root.finalUrl];
  const discovered = new Set<string>([root.finalUrl.href]);
  const visited = new Set<string>();
  const pages: PageInspection[] = [];
  const assets: ScannedAsset[] = [];
  let inspectedAssetCount = 0;
  let failedPages = 0;
  let robotsSkipped = 0;
  let crawlLimitReached = false;

  while (queue.length && pages.length < MAX_CRAWL_PAGES && Date.now() < deadline && inspectedAssetCount < MAX_SITE_ASSETS) {
    const next = queue.shift() as URL;
    if (visited.has(next.href)) continue;
    visited.add(next.href);
    if (!isAllowedByRobots(next, robotsRules)) {
      robotsSkipped += 1;
      continue;
    }
    try {
      const page = await inspectPage(next, allowedHost, origin, deadline, MAX_SITE_ASSETS - inspectedAssetCount, next.href === root.finalUrl.href ? root : undefined);
      pages.push(page);
      assets.push(...page.assets);
      inspectedAssetCount += page.assets.length;
      for (const link of page.links) {
        if (discovered.size >= MAX_DISCOVERED_PAGES) break;
        const candidate = new URL(link);
        if (candidate.origin !== origin || discovered.has(candidate.href)) continue;
        discovered.add(candidate.href);
        if (robotsStatus === "unavailable" || !isAllowedByRobots(candidate, robotsRules)) {
          robotsSkipped += 1;
          continue;
        }
        queue.push(candidate);
      }
    } catch {
      failedPages += 1;
    }
  }

  crawlLimitReached = queue.length > 0 && (pages.length >= MAX_CRAWL_PAGES || Date.now() >= deadline || inspectedAssetCount >= MAX_SITE_ASSETS || discovered.size >= MAX_DISCOVERED_PAGES);
  const checks = aggregatePageChecks(pages);
  const pagesDiscovered = discovered.size;
  addCheck(checks, "crawl-coverage", "Same-origin crawl coverage", `Inspected ${pages.length} of ${pagesDiscovered} discovered same-origin pages.`, "info", "info", origin, `robots.txt ${robotsStatus}; ${robotsSkipped} excluded/unexpanded links; ${failedPages} page fetch failures; ${crawlLimitReached ? "crawl stopped at a safety limit" : "queue completed"}`);
  const weights: Record<Finding["severity"], number> = { critical: 25, high: 14, medium: 8, low: 3, info: 0 };
  const deductions = checks.filter((check) => check.status === "issue").reduce((sum, check) => sum + weights[check.severity], 0);
  const uniqueAssets = [...new Map(assets.map((asset) => [`${asset.kind}:${asset.url}`, asset])).values()];
  return { id: crypto.randomUUID(), targetUrl: root.finalUrl.href, scannedAt: new Date().toISOString(), score: Math.max(0, 100 - deductions), checks, assets: uniqueAssets };
}
import assert from "node:assert/strict";
import test from "node:test";
import { aggregatePageChecks, assessSecurityHeaders, extractSameOriginLinks, inspectHtmlResources, isAllowedByRobots, isValidSourceMap, parseRobotsRules } from "./scanner";

function checkStatus(headers: Headers, id: string) {
  return assessSecurityHeaders(headers, true).find((check) => check.id === id)?.status;
}

test("accepts concrete security header policies and records their evidence", () => {
  const headers = new Headers({
    "content-security-policy": "default-src 'self'; script-src 'self' 'nonce-abc'; style-src 'self'; frame-ancestors 'none'",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "x-frame-options": "DENY",
  });

  const checks = assessSecurityHeaders(headers, true);
  for (const id of ["csp", "hsts", "nosniff", "framing", "referrer", "permissions"]) {
    assert.equal(checks.find((check) => check.id === id)?.status, "pass", `${id} should pass`);
    assert.ok(checks.find((check) => check.id === id)?.evidence, `${id} should include evidence`);
  }
});

test("does not treat weak or malformed security headers as protected", () => {
  const headers = new Headers({
    "content-security-policy": "default-src *; script-src 'unsafe-inline' 'unsafe-eval'",
    "strict-transport-security": "max-age=0",
    "x-frame-options": "ALLOW-FROM https://example.test",
    "referrer-policy": "unsafe-url",
    "permissions-policy": "camera=*, geolocation=()",
  });

  for (const id of ["csp", "hsts", "framing", "referrer", "permissions"]) {
    assert.equal(checkStatus(headers, id), "issue", `${id} should not pass on presence alone`);
  }
});

test("requires a script policy in CSP and accepts a strict referrer fallback", () => {
  const cspWithoutScriptPolicy = new Headers({ "content-security-policy": "upgrade-insecure-requests" });
  assert.equal(checkStatus(cspWithoutScriptPolicy, "csp"), "issue");
  const strictFallback = new Headers({ "referrer-policy": "unknown-policy, strict-origin-when-cross-origin" });
  assert.equal(checkStatus(strictFallback, "referrer"), "pass");
});

test("parses actual HTML resource attributes and ignores markup-like script text", () => {
  const result = inspectHtmlResources(`
    <html><head>
      <script src="/app.js"></script>
      <script src="https://cdn.example.test/vendor.js"></script>
      <script src="https://cdn.example.test/pinned.js" integrity="sha384-test"></script>
      <link rel="stylesheet" href="/site.css">
      <img src="http://images.example.test/photo.png">
      <div style="background-image: url('http://images.example.test/bg.png')"></div>
      <script>const example = '<img src="http://not-a-resource.test/fake.png">';</script>
    </head></html>
  `, "https://site.example.test/");

  assert.equal(result.mixedContentUrls.length, 2);
  assert.equal(result.thirdPartyWithoutIntegrity.length, 1);
  assert.equal(result.assetTargets.length, 2);
  assert.deepEqual(result.assetTargets.map((asset) => asset.kind), ["script", "stylesheet"]);
});

test("extracts only normalized same-origin page links for crawling", () => {
  const links = extractSameOriginLinks(`
    <a href="/about#team">About</a>
    <a href="https://site.example.test/pricing?plan=pro">Pricing</a>
    <a href="https://outside.example.test/">External</a>
    <a href="/app.js">Script</a>
    <a href="/logout">Logout</a>
    <a href="/private" rel="nofollow">No follow</a>
    <a href="mailto:help@site.example.test">Email</a>
    <a href="#section">Fragment</a>
  `, "https://site.example.test/");

  assert.deepEqual(links, ["https://site.example.test/about", "https://site.example.test/pricing?plan=pro", "https://site.example.test/"]);
});

test("applies the matching robots.txt group and most-specific allow rule", () => {
  const rules = parseRobotsRules(`
    User-agent: OtherBot
    Disallow: /

    User-agent: PerimeterSecurityScanner
    Disallow: /private
    Allow: /private/public

    User-agent: *
    Disallow: /admin
  `);
  assert.equal(isAllowedByRobots(new URL("https://site.example.test/private/account"), rules), false);
  assert.equal(isAllowedByRobots(new URL("https://site.example.test/private/public"), rules), true);
  assert.equal(isAllowedByRobots(new URL("https://site.example.test/admin"), rules), false);
  assert.equal(isAllowedByRobots(new URL("https://site.example.test/about"), rules), true);
});

test("aggregates duplicate checks with the number and paths of affected pages", () => {
  const makePage = (path: string, status: "issue" | "pass") => ({
    url: new URL(`https://site.example.test${path}`),
    assets: [],
    links: [],
    checks: [{
      id: "csp",
      title: "Content Security Policy",
      detail: status === "issue" ? "Weak script policy." : "Strict policy.",
      severity: "medium" as const,
      status,
      evidence: status === "issue" ? "unsafe-inline" : "strict-src",
      recommendation: "Use a strict script policy.",
    }],
  });
  const aggregated = aggregatePageChecks([makePage("/", "issue"), makePage("/account", "issue"), makePage("/about", "pass")]);
  assert.equal(aggregated.length, 1);
  assert.equal(aggregated[0].status, "issue");
  assert.match(aggregated[0].detail, /2 of 3 inspected pages/);
  assert.match(aggregated[0].evidence ?? "", /\//);
  assert.match(aggregated[0].evidence ?? "", /\/account/);
});

test("requires a structurally valid version 3 source map", () => {
  assert.equal(isValidSourceMap(JSON.stringify({ version: 3, sources: ["src/app.ts"], names: [], mappings: "AAAA" })), true);
  assert.equal(isValidSourceMap(JSON.stringify({ version: 3, sections: [{ offset: { line: 0, column: 0 }, map: { version: 3, sources: ["src/a.ts"], names: [], mappings: "AAAA" } }] })), true);
  assert.equal(isValidSourceMap(JSON.stringify({ version: 3, sections: [{ offset: { line: 0, column: 0 }, map: { version: 3 } }] })), false);
  assert.equal(isValidSourceMap(JSON.stringify({ version: 3, sources: "src/app.ts", names: [], mappings: "AAAA" })), false);
  assert.equal(isValidSourceMap("<!doctype html><title>Not a map</title>"), false);
  assert.equal(isValidSourceMap("not json"), false);
});
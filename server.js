/**
 * Keikomik Mirror Proxy Server
 *
 * Full reverse-proxy that mirrors keikomik.web.id with proper SEO handling:
 * - Rewrites all URLs (HTML, CSS, JS, sitemap, robots.txt) to mirror domain
 * - Fixes canonical tags, og:url, alternate links
 * - Rewrites structured data (JSON-LD, microdata) to avoid duplicate content
 * - Proxies and rewrites sitemap.xml automatically
 * - Rewrites robots.txt Sitemap directive
 * - Rewrites redirect Location headers
 * - Adds proper caching headers
 */

const express = require("express");
const http = require("http");
const https = require("https");
const { URL } = require("url");
const zlib = require("zlib");
const crypto = require("crypto");
const compression = require("compression");

// ─── CONFIG ────────────────────────────────────────────────────────────────────
const ORIGIN_HOST = process.env.ORIGIN_HOST || "keikomik.web.id";
const ORIGIN_PROTOCOL = process.env.ORIGIN_PROTOCOL || "https";
const ORIGIN_BASE = `${ORIGIN_PROTOCOL}://${ORIGIN_HOST}`;
const PORT = parseInt(process.env.PORT, 10) || 3000;
// Mirror domain — set this to your actual mirror domain
const MIRROR_HOST = process.env.MIRROR_HOST || "";
const MIRROR_PROTOCOL = process.env.MIRROR_PROTOCOL || "https";

// ─── VERCEL FIREWALL BYPASS ────────────────────────────────────────────────────
// Solves Vercel's proof-of-work challenge server-side so users never see it.
// Caches the bypass cookie and auto-refreshes when expired.

let vercelBypassCookie = "";
let vercelCookieExpiry = 0;

/**
 * SHA-256 hash of a string, returned as hex.
 */
async function sha256(str) {
  const hash = crypto.createHash("sha256").update(str).digest("hex");
  return hash;
}

/**
 * Find a random key such that sha256(prefix + key) starts with requiredPrefix.
 */
async function findMatchingKey(prefix, requiredPrefix) {
  while (true) {
    const key = Math.random().toString(36).substring(2, 15);
    const hash = await sha256(prefix + key);
    if (hash.startsWith(requiredPrefix)) {
      return { key, hash };
    }
  }
}

/**
 * Solve a Vercel challenge token (proof-of-work).
 */
async function solveVercelChallenge(challengeToken) {
  const parts = challengeToken.split(".");
  const decodedToken = Buffer.from(parts[3], "base64").toString("utf-8");
  const [prefix, suffix, startHash, iterations] = decodedToken.split(";");
  let currentHash = startHash;
  const keys = [];

  for (let i = 0; i < Number(iterations); i++) {
    const { key, hash } = await findMatchingKey(suffix, currentHash);
    keys.push(key);
    currentHash = hash.slice(-currentHash.length);
  }

  return keys.join(";");
}

/**
 * Submit the solved challenge to Vercel and get the bypass cookie.
 */
function submitVercelSolution(challengeToken, solution) {
  return new Promise((resolve, reject) => {
    const url = `${ORIGIN_BASE}/.well-known/vercel/security/request-challenge`;
    const parsed = new URL(url);

    const options = {
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname,
      method: "POST",
      headers: {
        host: ORIGIN_HOST,
        "x-vercel-challenge-token": challengeToken,
        "x-vercel-challenge-solution": solution,
        "content-length": "0",
      },
      timeout: 30000,
    };

    const transport = parsed.protocol === "https:" ? https : http;
    const req = transport.request(options, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        // Extract set-cookie headers
        const setCookies = res.headers["set-cookie"] || [];
        resolve({ status: res.statusCode, setCookies, headers: res.headers });
      });
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("Vercel challenge submit timed out")); });
    req.end();
  });
}

/**
 * Detect if a response body is a Vercel firewall challenge page.
 * Returns the challenge token if found, null otherwise.
 */
function detectVercelChallenge(bodyStr) {
  if (!bodyStr.includes("_vcrct")) return null;
  const match = bodyStr.match(/window\._vcrct="([^"]+)"/);
  return match ? match[1] : null;
}

/**
 * Parse Set-Cookie headers and extract cookie name=value pairs.
 */
function parseCookies(setCookieHeaders) {
  return setCookieHeaders.map(c => c.split(";")[0]).join("; ");
}

/**
 * Solve the Vercel challenge and cache the bypass cookie.
 * Returns the cookie string to use in subsequent requests.
 */
async function obtainVercelBypass(challengeToken) {
  console.log("[VERCEL] Solving firewall challenge...");
  const solution = await solveVercelChallenge(challengeToken);
  console.log("[VERCEL] Challenge solved, submitting...");
  const result = await submitVercelSolution(challengeToken, solution);
  console.log("[VERCEL] Submit status:", result.status);

  if (result.status === 204 || result.status === 200) {
    const cookie = parseCookies(result.setCookies);
    vercelBypassCookie = cookie;
    // Cache for 55 minutes (Vercel cookies typically last ~1 hour)
    vercelCookieExpiry = Date.now() + 55 * 60 * 1000;
    console.log("[VERCEL] Bypass cookie obtained:", cookie ? "yes" : "empty");
    return cookie;
  } else {
    console.error("[VERCEL] Challenge submission failed:", result.status);
    return "";
  }
}

/**
 * Get cached bypass cookie if still valid.
 */
function getVercelCookie() {
  if (vercelBypassCookie && Date.now() < vercelCookieExpiry) {
    return vercelBypassCookie;
  }
  return "";
}

// ─── AD BLOCKING CONFIG ────────────────────────────────────────────────────────
// Domains known to serve ads, tracking pixels, and redirect hijackers
const BLOCKED_AD_DOMAINS = [
  "detoxifylagoonsnugness.com",
  "cdn.bncloudfl.com",
  "bncloudfl.com",
  // Common ad networks used by manga/komik sites
  "juicyads.com",
  "exoclick.com",
  "exosrv.com",
  "tsyndicate.com",
  "tsynd.com",
  "hilltopads.net",
  "hilltopads.com",
  "hil.media",
  "richads.com",
  "popads.net",
  "popcash.net",
  "propellerads.com",
  "propellerclick.com",
  "clickadu.com",
  "trafficjunky.com",
  "adsterra.com",
  "a-ads.com",
  "monetag.com",
  "surfe.pro",
  "mondiad.com",
  "disqus.com",
];

// CSS selectors for ad elements to remove from HTML
const AD_SELECTORS = [
  // data-cl-spot ad containers (the main culprit from hilltopads)
  '[data-cl-spot]',
  // Banner containers by ID pattern
  '[id^="hil-"]',
  '[id^="hil_"]',
  // Common ad class names
  '[class*="adsbygoogle"]',
  '.ads-container',
  '.ad-container',
  '.ad-wrapper',
  '.ad-banner',
  '[id*="-ads-"]',
  '[id*="_ads_"]',
  // Popup / overlay / redirect hijack elements
  '[class*="popup-ad"]',
  '[class*="overlay-ad"]',
  'div[onclick*="window.open"]',
  'a[onclick*="window.open"]',
];

// Script patterns that indicate ad/redirect scripts
const AD_SCRIPT_PATTERNS = [
  /hilltopads/i,
  /data-cl-spot/i,
  /\.onclick\s*=.*window\.open/i,
  /popunder/i,
  /popUnder/i,
  /clickunder/i,
  /window\.open\s*\(/i,
  /document\.createElement.*iframe/i,
  /interstitial/i,
  /exoclick/i,
  /tsyndicate/i,
  /surfe\.pro/i,
  /monetag/i,
  /clickadu/i,
];

// Patterns to strip from JS content (neutralize ad loading code)
const AD_JS_STRIP_PATTERNS = [
  // hilltopads spot loader patterns
  /['"]data-cl-spot['"]/g,
  /data-cl-spot/g,
  // Direct domain references in JS strings
  /detoxifylagoonsnugness\.com/g,
  /cdn\.bncloudfl\.com/g,
  /bncloudfl\.com/g,
  /hilltopads\.net/g,
  /hilltopads\.com/g,
  /hil\.media/g,
];

/**
 * Strip ad-related code from JavaScript content.
 * Neutralizes ad domain references and ad loader patterns.
 */
function stripAdsFromJs(jsContent) {
  let result = jsContent;
  // Neutralize blocked domain strings in JS by replacing with invalid domain
  BLOCKED_AD_DOMAINS.forEach(domain => {
    // Replace the domain with a blocked placeholder that won't resolve
    const escaped = domain.replace(/\./g, '\\.');
    const re = new RegExp(escaped.replace(/\\\\\./g, '\\.'), 'g');
    result = result.split(domain).join('blocked.invalid');
  });
  // Remove data-cl-spot attribute references
  result = result.split('data-cl-spot').join('data-blocked-spot');
  // Neutralize hil-banner ID patterns
  result = result.replace(/hil-banner[A-Za-z0-9]*/g, 'blocked-banner');
  result = result.replace(/hil_banner[A-Za-z0-9]*/g, 'blocked-banner');
  return result;
}

/**
 * Generate Content-Security-Policy header that blocks ad domains.
 */
function generateCSP() {
  const blockedDomains = BLOCKED_AD_DOMAINS.map(d => `*.${d} ${d}`).join(' ');
  // Block ad domains from scripts, images, frames, connect, and default
  return [
    `default-src * 'unsafe-inline' 'unsafe-eval' data: blob:`,
    `script-src * 'unsafe-inline' 'unsafe-eval'`,
    `img-src * data: blob:`,
    `frame-src 'self'`,
    `child-src 'self'`,
  ].join('; ');
}

/**
 * Check if a URL/domain is a known ad domain.
 */
function isBlockedAdDomain(urlStr) {
  try {
    const hostname = urlStr.includes('://') ? new URL(urlStr).hostname : urlStr;
    return BLOCKED_AD_DOMAINS.some(blocked =>
      hostname === blocked || hostname.endsWith('.' + blocked)
    );
  } catch {
    // Check as raw string
    return BLOCKED_AD_DOMAINS.some(blocked => urlStr.includes(blocked));
  }
}

// ─── HELPERS ───────────────────────────────────────────────────────────────────

/**
 * Determine the mirror base URL from the incoming request.
 * Falls back to MIRROR_HOST env, then request Host header.
 * Strips internal PORT from host to avoid :3000 leaking into URLs.
 */
function getMirrorBase(req) {
  let host = MIRROR_HOST || req.headers["x-forwarded-host"] || req.headers.host || req.hostname;
  // Strip internal port — behind a reverse proxy (Codespaces, Railway, Render)
  // the external port differs from the internal PORT. Including it breaks links.
  const portSuffix = ":" + PORT;
  if (host.endsWith(portSuffix)) {
    host = host.slice(0, -portSuffix.length);
  }
  const proto =
    MIRROR_PROTOCOL ||
    req.headers["x-forwarded-proto"] ||
    (req.secure ? "https" : "http");
  return `${proto}://${host}`;
}

/**
 * Replace all occurrences of origin domain with mirror domain in text.
 */
function rewriteUrls(text, mirrorBase) {
  if (!text) return text;

  // Replace full origin URLs (both http and https variants)
  let result = text;
  result = result.split(`https://${ORIGIN_HOST}`).join(mirrorBase);
  result = result.split(`http://${ORIGIN_HOST}`).join(mirrorBase);
  // Also handle protocol-relative URLs
  result = result.split(`//${ORIGIN_HOST}`).join(`//${new URL(mirrorBase).host}`);
  return result;
}

/**
 * Raw fetch from origin. Returns { status, headers, body (Buffer) }.
 * Includes bypass cookie if provided.
 */
function fetchFromOriginRaw(path, method, reqHeaders, reqBody, extraCookie) {
  return new Promise((resolve, reject) => {
    const originUrl = `${ORIGIN_BASE}${path}`;
    const parsed = new URL(originUrl);

    const headers = { ...reqHeaders };
    // Overwrite host to origin
    headers["host"] = ORIGIN_HOST;
    // Remove encoding so we get raw body (we'll compress ourselves)
    delete headers["accept-encoding"];
    // Remove if-modified-since / if-none-match to always get fresh content for rewriting
    delete headers["if-modified-since"];
    delete headers["if-none-match"];

    // Inject Vercel bypass cookie
    if (extraCookie) {
      const existing = headers["cookie"] || "";
      headers["cookie"] = existing ? `${existing}; ${extraCookie}` : extraCookie;
    }

    const options = {
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname + parsed.search,
      method: method,
      headers: headers,
      timeout: 30000,
    };

    const transport = parsed.protocol === "https:" ? https : http;

    const proxyReq = transport.request(options, (proxyRes) => {
      const chunks = [];
      proxyRes.on("data", (chunk) => chunks.push(chunk));
      proxyRes.on("end", () => {
        const rawBody = Buffer.concat(chunks);
        // Decompress if needed
        const encoding = proxyRes.headers["content-encoding"];
        if (encoding === "gzip") {
          zlib.gunzip(rawBody, (err, decoded) => {
            if (err) return resolve({ status: proxyRes.statusCode, headers: proxyRes.headers, body: rawBody });
            resolve({ status: proxyRes.statusCode, headers: proxyRes.headers, body: decoded });
          });
        } else if (encoding === "br") {
          zlib.brotliDecompress(rawBody, (err, decoded) => {
            if (err) return resolve({ status: proxyRes.statusCode, headers: proxyRes.headers, body: rawBody });
            resolve({ status: proxyRes.statusCode, headers: proxyRes.headers, body: decoded });
          });
        } else if (encoding === "deflate") {
          zlib.inflate(rawBody, (err, decoded) => {
            if (err) return resolve({ status: proxyRes.statusCode, headers: proxyRes.headers, body: rawBody });
            resolve({ status: proxyRes.statusCode, headers: proxyRes.headers, body: decoded });
          });
        } else {
          resolve({ status: proxyRes.statusCode, headers: proxyRes.headers, body: rawBody });
        }
      });
    });

    proxyReq.on("error", reject);
    proxyReq.on("timeout", () => {
      proxyReq.destroy();
      reject(new Error("Origin request timed out"));
    });

    if (reqBody) {
      proxyReq.write(reqBody);
    }
    proxyReq.end();
  });
}

/**
 * Fetch from origin with automatic Vercel firewall bypass.
 * If origin returns a challenge page, solve it, get cookie, and retry.
 */
async function fetchFromOrigin(path, method, reqHeaders, reqBody) {
  // First try with cached bypass cookie
  const cookie = getVercelCookie();
  let result = await fetchFromOriginRaw(path, method, reqHeaders, reqBody, cookie);

  // Check if response is a Vercel challenge page
  const bodyStr = result.body.toString("utf-8");
  const challengeToken = detectVercelChallenge(bodyStr);

  if (challengeToken) {
    // Solve the challenge and get a new bypass cookie
    try {
      const newCookie = await obtainVercelBypass(challengeToken);
      if (newCookie) {
        // Retry the original request with the new cookie
        result = await fetchFromOriginRaw(path, method, reqHeaders, reqBody, newCookie);
      }
    } catch (err) {
      console.error("[VERCEL] Failed to solve challenge:", err.message);
      // Return the original challenge response as fallback
    }
  }

  return result;
}

/**
 * Detect if a content-type is textual (HTML, XML, CSS, JS, JSON, etc.)
 */
function isTextContent(contentType) {
  if (!contentType) return false;
  const textTypes = [
    "text/",
    "application/json",
    "application/javascript",
    "application/xml",
    "application/xhtml",
    "application/rss",
    "application/atom",
    "application/x-javascript",
    "image/svg+xml",
  ];
  return textTypes.some((t) => contentType.includes(t));
}

/**
 * Determine if this is an HTML response.
 */
function isHtmlContent(contentType) {
  if (!contentType) return false;
  return contentType.includes("text/html") || contentType.includes("application/xhtml");
}

/**
 * Determine if this is an XML response (sitemap, RSS, etc.)
 */
function isXmlContent(contentType) {
  if (!contentType) return false;
  return (
    contentType.includes("text/xml") ||
    contentType.includes("application/xml") ||
    contentType.includes("application/rss") ||
    contentType.includes("application/atom")
  );
}

// ─── HTML REWRITING (using cheerio for robust parsing) ─────────────────────────
const cheerio = require("cheerio");

/**
 * Rewrite HTML content for SEO-correct mirroring.
 */
function rewriteHtml(html, mirrorBase) {
  const $ = cheerio.load(html, { decodeEntities: false });
  const mirrorUrl = new URL(mirrorBase);
  const mirrorHost = mirrorUrl.host;

  // 1. Rewrite <link rel="canonical">
  $('link[rel="canonical"]').each(function () {
    const href = $(this).attr("href");
    if (href) {
      $(this).attr("href", rewriteUrls(href, mirrorBase));
    }
  });

  // 2. Rewrite <link rel="alternate">
  $('link[rel="alternate"]').each(function () {
    const href = $(this).attr("href");
    if (href) {
      $(this).attr("href", rewriteUrls(href, mirrorBase));
    }
  });

  // 3. Rewrite Open Graph and Twitter meta tags
  $('meta[property="og:url"], meta[name="twitter:url"]').each(function () {
    const content = $(this).attr("content");
    if (content) {
      $(this).attr("content", rewriteUrls(content, mirrorBase));
    }
  });
  $('meta[property="og:image"], meta[name="twitter:image"]').each(function () {
    const content = $(this).attr("content");
    if (content) {
      $(this).attr("content", rewriteUrls(content, mirrorBase));
    }
  });
  $('meta[property="og:site_name"]').each(function () {
    const content = $(this).attr("content");
    if (content) {
      $(this).attr("content", rewriteUrls(content, mirrorBase));
    }
  });

  // 4. Rewrite all href and src attributes
  $("[href]").each(function () {
    const href = $(this).attr("href");
    if (href && (href.includes(ORIGIN_HOST) || href.includes(`//${ORIGIN_HOST}`))) {
      $(this).attr("href", rewriteUrls(href, mirrorBase));
    }
  });
  $("[src]").each(function () {
    const src = $(this).attr("src");
    if (src && (src.includes(ORIGIN_HOST) || src.includes(`//${ORIGIN_HOST}`))) {
      $(this).attr("src", rewriteUrls(src, mirrorBase));
    }
  });
  $("[srcset]").each(function () {
    const srcset = $(this).attr("srcset");
    if (srcset && srcset.includes(ORIGIN_HOST)) {
      $(this).attr("srcset", rewriteUrls(srcset, mirrorBase));
    }
  });

  // 5. Rewrite <form> action attributes
  $("form[action]").each(function () {
    const action = $(this).attr("action");
    if (action && action.includes(ORIGIN_HOST)) {
      $(this).attr("action", rewriteUrls(action, mirrorBase));
    }
  });

  // 6. Rewrite JSON-LD structured data
  $('script[type="application/ld+json"]').each(function () {
    try {
      const raw = $(this).html();
      if (raw) {
        const rewritten = rewriteUrls(raw, mirrorBase);
        // Validate it's still valid JSON
        JSON.parse(rewritten);
        $(this).html(rewritten);
      }
    } catch (e) {
      // If JSON-LD is malformed, still try text replacement
      const raw = $(this).html();
      if (raw) {
        $(this).html(rewriteUrls(raw, mirrorBase));
      }
    }
  });

  // 7. Ensure canonical tag exists — add one if missing
  if ($('link[rel="canonical"]').length === 0) {
    // We'll inject it based on current request path (added later in handler)
    $("head").append(`<!-- canonical-placeholder -->`);
  }

  // 8. Rewrite inline styles that may reference origin
  $("[style]").each(function () {
    const style = $(this).attr("style");
    if (style && style.includes(ORIGIN_HOST)) {
      $(this).attr("style", rewriteUrls(style, mirrorBase));
    }
  });

  // 9. Rewrite inline scripts that reference origin domain
  $("script:not([src])").each(function () {
    const content = $(this).html();
    if (content && content.includes(ORIGIN_HOST)) {
      // Only rewrite domain references, not ld+json (already handled)
      if ($(this).attr("type") !== "application/ld+json") {
        $(this).html(rewriteUrls(content, mirrorBase));
      }
    }
  });

  // ─── AD REMOVAL ────────────────────────────────────────────────────

  // 10. Remove ad container elements (data-cl-spot, hil-banner*, etc.)
  AD_SELECTORS.forEach(selector => {
    $(selector).remove();
  });

  // 11. Remove all elements with src/href pointing to ad domains
  $('[src]').each(function () {
    const src = $(this).attr('src') || '';
    if (isBlockedAdDomain(src)) {
      $(this).remove();
    }
  });
  $('[href]').each(function () {
    const href = $(this).attr('href') || '';
    if (isBlockedAdDomain(href)) {
      // If it's wrapping content (like an <a> tag), unwrap instead of removing
      const tag = (this.tagName || this.name || '').toLowerCase();
      if (tag === 'a') {
        $(this).replaceWith($(this).html());
      } else {
        $(this).remove();
      }
    }
  });

  // 12. Remove external scripts from ad domains
  $('script[src]').each(function () {
    const src = $(this).attr('src') || '';
    if (isBlockedAdDomain(src)) {
      $(this).remove();
    }
  });

  // 13. Remove inline scripts that contain ad/redirect patterns
  $('script:not([src]):not([type="application/ld+json"]):not([id="__NEXT_DATA__"])').each(function () {
    const content = $(this).html() || '';
    // Check against ad script patterns
    const isAdScript = AD_SCRIPT_PATTERNS.some(pattern => pattern.test(content));
    // Also check if it references blocked domains
    const refsBlockedDomain = BLOCKED_AD_DOMAINS.some(d => content.includes(d));
    if (isAdScript || refsBlockedDomain) {
      $(this).remove();
    }
  });

  // 14. Remove iframes that load ad content
  $('iframe').each(function () {
    const src = $(this).attr('src') || '';
    if (!src || isBlockedAdDomain(src)) {
      $(this).remove();
    }
  });

  // 15. Remove elements that are likely ad overlays (hidden tracking pixels, etc.)
  $('img[style*="display: none"], img[style*="display:none"]').each(function () {
    const src = $(this).attr('src') || '';
    // Hidden images are usually tracking pixels — remove if from ad domain
    if (isBlockedAdDomain(src)) {
      $(this).remove();
    }
  });

  // 16. Clean up parent divs that only contained ads and are now empty
  $('div').each(function () {
    const el = $(this);
    const html = el.html();
    if (html !== null && html.trim() === '' && !el.attr('id')?.startsWith('__')) {
      // Only remove truly empty wrapper divs that have ad-related IDs
      const id = el.attr('id') || '';
      if (id.startsWith('hil-') || id.startsWith('hil_')) {
        el.remove();
      }
    }
  });

  // 17. Clean __NEXT_DATA__ scriptLoader to remove ad-related script loaders
  $('#__NEXT_DATA__').each(function () {
    try {
      const raw = $(this).html();
      if (raw) {
        const data = JSON.parse(raw);
        if (data.scriptLoader && Array.isArray(data.scriptLoader)) {
          data.scriptLoader = data.scriptLoader.filter(script => {
            const src = script.src || '';
            const children = script.children || '';
            // Keep Google Analytics, remove everything else suspicious
            if (isBlockedAdDomain(src)) return false;
            if (BLOCKED_AD_DOMAINS.some(d => children.includes(d))) return false;
            if (/hilltopads|data-cl-spot|popunder|clickunder/i.test(src + children)) return false;
            return true;
          });
        }
        $(this).html(JSON.stringify(data));
      }
    } catch (e) { /* ignore parse errors */ }
  });

  // 18. Inject AGGRESSIVE client-side ad blocker with MutationObserver
  $('head').prepend(`<script>
    // === KEIKOMIK MIRROR AD BLOCKER ===
    (function() {
      'use strict';
      var BLOCKED = ${JSON.stringify(BLOCKED_AD_DOMAINS)};
      var AD_SELECTORS = [
        '[data-cl-spot]','[data-blocked-spot]','[id^="hil-"]','[id^="hil_"]',
        'iframe[src*="detoxify"]','iframe[src*="bncloudfl"]',
        'iframe[src*="hilltopads"]','iframe[src*="popads"]',
        'iframe[src*="exoclick"]','iframe[src*="clickadu"]',
        'iframe:not([src])','iframe[src=""]','iframe[src="about:blank"]'
      ];
      function isDomainBlocked(s) {
        if (!s) return false;
        return BLOCKED.some(function(d) { return s.indexOf(d) !== -1; });
      }
      function killAds() {
        AD_SELECTORS.forEach(function(sel) {
          document.querySelectorAll(sel).forEach(function(el) { el.remove(); });
        });
        // Remove any img from ad domains
        document.querySelectorAll('img').forEach(function(img) {
          if (isDomainBlocked(img.src)) img.remove();
        });
        // Remove scripts from ad domains
        document.querySelectorAll('script[src]').forEach(function(s) {
          if (isDomainBlocked(s.src)) s.remove();
        });
        // Remove any link/a pointing to ad domains
        document.querySelectorAll('a[href]').forEach(function(a) {
          if (isDomainBlocked(a.href)) {
            a.removeAttribute('href');
            a.style.cursor = 'default';
          }
        });
        // Remove hidden tracking iframes
        document.querySelectorAll('iframe').forEach(function(f) {
          if (!f.src || isDomainBlocked(f.src) || f.offsetWidth < 2 || f.offsetHeight < 2) {
            f.remove();
          }
        });
        // Remove ad overlay divs with suspicious inline styles
        document.querySelectorAll('div[style]').forEach(function(d) {
          var s = d.style;
          if ((s.position === 'fixed' || s.position === 'absolute') &&
              (s.zIndex > 9000 || parseInt(s.zIndex) > 9000) &&
              d.querySelector('img, iframe, a')) {
            d.remove();
          }
        });
      }
      // Block window.open completely
      window.open = function() { return null; };
      // Override createElement to block iframe creation for ads
      var origCreate = document.createElement.bind(document);
      document.createElement = function(tag) {
        var el = origCreate(tag);
        if (tag.toLowerCase() === 'iframe') {
          var origSetAttr = el.setAttribute.bind(el);
          el.setAttribute = function(name, value) {
            if (name === 'src' && isDomainBlocked(value)) return;
            return origSetAttr(name, value);
          };
          Object.defineProperty(el, 'src', {
            set: function(v) { if (!isDomainBlocked(v)) origSetAttr('src', v); },
            get: function() { return el.getAttribute('src'); }
          });
        }
        return el;
      };
      // Block fetch/XHR to ad domains
      var origFetch = window.fetch;
      window.fetch = function(url) {
        if (typeof url === 'string' && isDomainBlocked(url)) {
          return Promise.resolve(new Response('', {status: 204}));
        }
        return origFetch.apply(this, arguments);
      };
      var origXhrOpen = XMLHttpRequest.prototype.open;
      XMLHttpRequest.prototype.open = function(method, url) {
        if (typeof url === 'string' && isDomainBlocked(url)) {
          this._blocked = true;
          return;
        }
        return origXhrOpen.apply(this, arguments);
      };
      var origXhrSend = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.send = function() {
        if (this._blocked) return;
        return origXhrSend.apply(this, arguments);
      };
      // Run immediately
      killAds();
      // Run on DOM ready
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', killAds);
      }
      // Run on full load
      window.addEventListener('load', function() { killAds(); setTimeout(killAds, 500); setTimeout(killAds, 1500); setTimeout(killAds, 3000); });
      // MutationObserver to catch dynamically injected ads
      var obs = new MutationObserver(function(mutations) {
        var dominated = false;
        mutations.forEach(function(m) {
          m.addedNodes.forEach(function(node) {
            if (node.nodeType !== 1) return;
            // Check if added node is an ad
            if (node.hasAttribute && node.hasAttribute('data-cl-spot')) { node.remove(); dominated = true; }
            if (node.hasAttribute && node.hasAttribute('data-blocked-spot')) { node.remove(); dominated = true; }
            var id = node.id || '';
            if (id.startsWith('hil-') || id.startsWith('hil_')) { node.remove(); dominated = true; }
            var tag = (node.tagName || '').toLowerCase();
            if (tag === 'iframe') {
              var src = node.src || node.getAttribute('src') || '';
              if (!src || isDomainBlocked(src)) { node.remove(); dominated = true; }
            }
            if (tag === 'img' && isDomainBlocked(node.src || '')) { node.remove(); dominated = true; }
            if (tag === 'script' && isDomainBlocked(node.src || '')) { node.remove(); dominated = true; }
            // Check children
            if (!dominated && node.querySelectorAll) {
              node.querySelectorAll('[data-cl-spot],[data-blocked-spot],[id^="hil-"],[id^="hil_"],iframe').forEach(function(child) { child.remove(); });
            }
          });
        });
      });
      obs.observe(document.documentElement, { childList: true, subtree: true });
      // Block click hijacking
      document.addEventListener('click', function(e) {
        var t = e.target;
        while (t && t !== document.body) {
          var href = t.getAttribute && (t.getAttribute('href') || '');
          if (isDomainBlocked(href)) { e.preventDefault(); e.stopPropagation(); return false; }
          t = t.parentElement;
        }
      }, true);
      // Prevent body onclick redirect hijacking
      Object.defineProperty(document.body || document.documentElement, 'onclick', {
        set: function() {},
        get: function() { return null; }
      });
    })();
  </script>`);

  return $.html();
}

/**
 * Ensure the HTML has a proper canonical tag for the given path.
 */
function ensureCanonical(html, mirrorBase, requestPath) {
  const canonicalUrl = `${mirrorBase}${requestPath}`;

  // Replace placeholder if we added one
  html = html.replace(
    "<!-- canonical-placeholder -->",
    `<link rel="canonical" href="${canonicalUrl}" />`
  );

  return html;
}

/**
 * Rewrite XML content (sitemaps, RSS feeds).
 */
function rewriteXml(xml, mirrorBase) {
  return rewriteUrls(xml, mirrorBase);
}

/**
 * Generate a clean robots.txt pointing to the mirror's sitemap.
 */
function generateRobotsTxt(originalRobots, mirrorBase) {
  let robots = rewriteUrls(originalRobots, mirrorBase);

  // Ensure Sitemap directive exists
  if (!robots.toLowerCase().includes("sitemap:")) {
    robots += `\n\nSitemap: ${mirrorBase}/sitemap.xml\n`;
  }

  return robots;
}

// ─── EXPRESS APP ────────────────────────────────────────────────────────────────
const app = express();

// Enable gzip compression for responses
app.use(compression());

// Trust proxy (for Railway, Render, etc.)
app.set("trust proxy", true);

// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok", origin: ORIGIN_HOST });
});

// ─── MAIN PROXY HANDLER ────────────────────────────────────────────────────────
app.all("*", async (req, res) => {
  try {
    const mirrorBase = getMirrorBase(req);
    const requestPath = req.originalUrl;

    // ─── BLOCK AD DOMAIN REQUESTS ────────────────────────────────────
    // If the request path somehow routes to an ad, or referer is ad, block it
    const fullUrl = `${mirrorBase}${requestPath}`;
    if (BLOCKED_AD_DOMAINS.some(d => requestPath.includes(d))) {
      return res.status(204).end();
    }

    // Collect request body for POST/PUT/PATCH
    let reqBody = null;
    if (["POST", "PUT", "PATCH"].includes(req.method)) {
      reqBody = await new Promise((resolve, reject) => {
        const chunks = [];
        req.on("data", (chunk) => chunks.push(chunk));
        req.on("end", () => resolve(Buffer.concat(chunks)));
        req.on("error", reject);
      });
    }

    // Build clean headers to forward
    const forwardHeaders = {};
    const skipHeaders = new Set([
      "host",
      "connection",
      "accept-encoding",
      "cf-connecting-ip",
      "cf-ray",
      "cf-visitor",
      "cf-ipcountry",
      "cdn-loop",
      "x-forwarded-for",
      "x-forwarded-proto",
      "x-forwarded-host",
      "x-forwarded-port",
    ]);

    for (const [key, value] of Object.entries(req.headers)) {
      if (!skipHeaders.has(key.toLowerCase())) {
        forwardHeaders[key] = value;
      }
    }

    // Fetch from origin
    const origin = await fetchFromOrigin(requestPath, req.method, forwardHeaders, reqBody);

    const contentType = origin.headers["content-type"] || "";

    // ─── HANDLE REDIRECTS ──────────────────────────────────────────────
    if ([301, 302, 303, 307, 308].includes(origin.status)) {
      let location = origin.headers["location"] || "";
      if (location) {
        location = rewriteUrls(location, mirrorBase);
        // If location is absolute but still pointing to origin, rewrite
        if (location.startsWith("/")) {
          location = `${mirrorBase}${location}`;
        }
      }
      res.set("Location", location);
      // Copy cache headers
      if (origin.headers["cache-control"]) {
        res.set("Cache-Control", origin.headers["cache-control"]);
      }
      return res.status(origin.status).end();
    }

    // ─── SET RESPONSE HEADERS ──────────────────────────────────────────
    const responseSkipHeaders = new Set([
      "content-encoding",
      "content-length",
      "transfer-encoding",
      "connection",
      "keep-alive",
      "alt-svc",
      "cf-ray",
      "cf-cache-status",
      "server",
      "x-powered-by",
      "strict-transport-security",
      "set-cookie",           // Don't leak Vercel/origin cookies to user
      "x-vercel-id",
      "x-vercel-cache",
    ]);

    for (const [key, value] of Object.entries(origin.headers)) {
      if (!responseSkipHeaders.has(key.toLowerCase())) {
        // Rewrite any header that might contain origin URLs
        if (typeof value === "string" && value.includes(ORIGIN_HOST)) {
          res.set(key, rewriteUrls(value, mirrorBase));
        } else {
          res.set(key, value);
        }
      }
    }

    // Add security headers
    res.set("X-Content-Type-Options", "nosniff");
    res.set("X-Frame-Options", "SAMEORIGIN");
    res.set("Referrer-Policy", "strict-origin-when-cross-origin");

    // Add Content-Security-Policy to block ad domains at browser level
    // Use a blocklist approach: allow everything EXCEPT ad domains
    // frame-src blocks ad iframes, everything else is permissive for site functionality
    res.set("Content-Security-Policy",
      `frame-src 'self'; ` +
      `child-src 'self';`
    );

    // ─── HANDLE 404 ────────────────────────────────────────────────────
    // Return the actual origin status; don't mask errors
    // But if origin returns 404, serve it properly so Google de-indexes cleanly
    if (origin.status === 404) {
      if (isHtmlContent(contentType)) {
        let html = origin.body.toString("utf-8");
        html = rewriteHtml(html, mirrorBase);
        html = ensureCanonical(html, mirrorBase, requestPath);
        res.set("Content-Type", contentType);
        return res.status(404).send(html);
      }
      return res.status(404).send(origin.body);
    }

    // ─── ROBOTS.TXT ────────────────────────────────────────────────────
    if (requestPath === "/robots.txt") {
      const robotsTxt = generateRobotsTxt(origin.body.toString("utf-8"), mirrorBase);
      res.set("Content-Type", "text/plain; charset=utf-8");
      res.set("Cache-Control", "public, max-age=3600");
      return res.status(200).send(robotsTxt);
    }

    // ─── SITEMAP HANDLING ──────────────────────────────────────────────
    if (
      requestPath.includes("sitemap") &&
      (requestPath.endsWith(".xml") || requestPath.endsWith(".xml.gz") || isXmlContent(contentType))
    ) {
      let xmlContent = origin.body.toString("utf-8");
      xmlContent = rewriteXml(xmlContent, mirrorBase);
      res.set("Content-Type", "application/xml; charset=utf-8");
      res.set("Cache-Control", "public, max-age=3600");
      return res.status(origin.status).send(xmlContent);
    }

    // ─── HTML CONTENT ──────────────────────────────────────────────────
    if (isHtmlContent(contentType)) {
      let html = origin.body.toString("utf-8");
      html = rewriteHtml(html, mirrorBase);
      html = ensureCanonical(html, mirrorBase, requestPath);
      res.set("Content-Type", contentType);
      return res.status(origin.status).send(html);
    }

    // ─── JAVASCRIPT CONTENT — strip ad code ──────────────────────────
    if (contentType.includes('javascript') || contentType.includes('application/x-javascript')) {
      let jsText = origin.body.toString("utf-8");
      jsText = rewriteUrls(jsText, mirrorBase);
      jsText = stripAdsFromJs(jsText);
      res.set("Content-Type", contentType);
      return res.status(origin.status).send(jsText);
    }

    // ─── OTHER TEXT CONTENT (CSS, XML, JSON, SVG) ──────────────────────
    if (isTextContent(contentType)) {
      let text = origin.body.toString("utf-8");
      text = rewriteUrls(text, mirrorBase);
      res.set("Content-Type", contentType);
      return res.status(origin.status).send(text);
    }

    // ─── BINARY CONTENT (images, fonts, etc.) ──────────────────────────
    // Pass through without modification
    return res.status(origin.status).send(origin.body);

  } catch (err) {
    console.error("[PROXY ERROR]", err.message);
    res.status(502).json({
      error: "Bad Gateway",
      message: "Failed to fetch from origin server",
    });
  }
});

// ─── START SERVER ──────────────────────────────────────────────────────────────
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Mirror proxy running on port ${PORT}`);
  console.log(`Origin: ${ORIGIN_BASE}`);
  console.log(`Set MIRROR_HOST env to your mirror domain for URL rewriting`);

  // Pre-warm: solve Vercel challenge at startup so first user request is fast
  (async () => {
    try {
      console.log("[VERCEL] Pre-warming bypass cookie...");
      const res = await fetchFromOriginRaw("/", "GET", {}, null, "");
      const bodyStr = res.body.toString("utf-8");
      const token = detectVercelChallenge(bodyStr);
      if (token) {
        await obtainVercelBypass(token);
        console.log("[VERCEL] Pre-warm complete — bypass cookie cached");
      } else {
        console.log("[VERCEL] No firewall challenge detected on origin (good)");
      }
    } catch (err) {
      console.log("[VERCEL] Pre-warm skipped:", err.message);
    }
  })();
});

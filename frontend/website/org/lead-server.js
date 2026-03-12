const http = require("node:http");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const crypto = require("node:crypto");

const HOST = process.env.HOST || "0.0.0.0";
const PORT = Number(process.env.PORT || 8787);
const PUBLIC_DIR = path.resolve(process.cwd(), process.env.PUBLIC_DIR || ".");
const LEAD_STORE_PATH = path.resolve(process.cwd(), process.env.LEAD_STORE_PATH || "./data/leads.jsonl");
const LEAD_RATE_WINDOW_MS = Number(process.env.LEAD_RATE_WINDOW_MS || 600000);
const LEAD_RATE_LIMIT = Number(process.env.LEAD_RATE_LIMIT || 10);
const LEAD_DAILY_LIMIT = Number(process.env.LEAD_DAILY_LIMIT || 50);
const LEAD_MAX_BODY_BYTES = Number(process.env.LEAD_MAX_BODY_BYTES || 65536);
const TRUST_PROXY = String(process.env.TRUST_PROXY || "true") === "true";
const ALLOWED_ORIGINS = new Set(
  String(process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean)
);
const LEAD_WEBHOOK_URL = String(process.env.LEAD_WEBHOOK_URL || "").trim();
const LEAD_WEBHOOK_TOKEN = String(process.env.LEAD_WEBHOOK_TOKEN || "").trim();
const LEAD_PII_SALT = String(process.env.LEAD_PII_SALT || "").trim();

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
  ".webp": "image/webp"
};

const ALLOWED_TYPES = new Set([
  "Venture Capital",
  "Private Equity",
  "Family Office",
  "Corporate Development",
  "Sovereign / Strategic Capital"
]);

const ALLOWED_REGIONS = new Set([
  "North America",
  "Europe",
  "MENA",
  "APAC",
  "Global / Multi-region",
  ""
]);

const rateLimiter = new Map();
let writeQueue = Promise.resolve();

function normalize(value) {
  return String(value || "")
    .replace(/\s+/g, " ")
    .trim();
}

function hashValue(value) {
  const hash = crypto.createHash("sha256");
  hash.update(value);
  if (LEAD_PII_SALT) {
    hash.update(LEAD_PII_SALT);
  }
  return hash.digest("hex");
}

function nowIso() {
  return new Date().toISOString();
}

function getClientIp(req) {
  if (TRUST_PROXY) {
    const forwarded = req.headers["x-forwarded-for"];
    if (forwarded) {
      return String(forwarded)
        .split(",")[0]
        .trim();
    }
  }
  return req.socket?.remoteAddress || "unknown";
}

function getRateLimit(ip) {
  const now = Date.now();
  const dayKey = new Date(now).toISOString().slice(0, 10);

  let bucket = rateLimiter.get(ip);
  if (!bucket) {
    bucket = { windowHits: [], dayKey, dayCount: 0 };
    rateLimiter.set(ip, bucket);
  }

  bucket.windowHits = bucket.windowHits.filter((ts) => now - ts < LEAD_RATE_WINDOW_MS);

  if (bucket.dayKey !== dayKey) {
    bucket.dayKey = dayKey;
    bucket.dayCount = 0;
  }

  if (bucket.windowHits.length >= LEAD_RATE_LIMIT) {
    const retryAfterMs = LEAD_RATE_WINDOW_MS - (now - bucket.windowHits[0]);
    return {
      limited: true,
      status: 429,
      retryAfterSeconds: Math.max(1, Math.ceil(retryAfterMs / 1000)),
      message: "Too many submissions from this IP. Try again shortly."
    };
  }

  if (bucket.dayCount >= LEAD_DAILY_LIMIT) {
    return {
      limited: true,
      status: 429,
      retryAfterSeconds: 3600,
      message: "Daily submission limit reached for this source."
    };
  }

  bucket.windowHits.push(now);
  bucket.dayCount += 1;

  return { limited: false };
}

async function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;

    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(Object.assign(new Error("Request body too large"), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => {
      resolve(Buffer.concat(chunks).toString("utf8"));
    });

    req.on("error", (error) => {
      reject(error);
    });
  });
}

function parseBody(req, rawBody) {
  const contentType = String(req.headers["content-type"] || "").toLowerCase();

  if (!rawBody) {
    return {};
  }

  if (contentType.includes("application/json")) {
    return JSON.parse(rawBody);
  }

  if (contentType.includes("application/x-www-form-urlencoded")) {
    const params = new URLSearchParams(rawBody);
    const output = {};
    params.forEach((value, key) => {
      output[key] = value;
    });
    return output;
  }

  throw Object.assign(new Error("Unsupported content type"), { status: 415 });
}

function validateLead(payload) {
  const lead = {
    name: normalize(payload.name),
    email: normalize(payload.email).toLowerCase(),
    institution: normalize(payload.institution),
    type: normalize(payload.type),
    region: normalize(payload.region),
    timeline: normalize(payload.timeline),
    message: normalize(payload.message),
    consent: payload.consent === true || payload.consent === "true" || payload.consent === "on",
    website: normalize(payload.website),
    startedAt: normalize(payload.startedAt),
    sourcePath: normalize(payload.sourcePath),
    sourceUrl: normalize(payload.sourceUrl)
  };

  const errors = [];

  if (lead.website) {
    return { valid: false, spam: true, errors: ["Spam detected"], lead };
  }

  if (!lead.name || lead.name.length < 2 || lead.name.length > 120) {
    errors.push("Name must be between 2 and 120 characters.");
  }

  if (!lead.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(lead.email) || lead.email.length > 150) {
    errors.push("Valid email is required.");
  }

  if (!lead.institution || lead.institution.length < 2 || lead.institution.length > 160) {
    errors.push("Institution must be between 2 and 160 characters.");
  }

  if (!lead.type || !ALLOWED_TYPES.has(lead.type)) {
    errors.push("Investor type is invalid.");
  }

  if (!ALLOWED_REGIONS.has(lead.region)) {
    errors.push("Region is invalid.");
  }

  if (lead.timeline.length > 120) {
    errors.push("Timeline must be 120 characters or fewer.");
  }

  if (lead.message.length > 2400) {
    errors.push("Message must be 2400 characters or fewer.");
  }

  if (!lead.consent) {
    errors.push("Consent is required.");
  }

  if (lead.startedAt) {
    const startedMs = Date.parse(lead.startedAt);
    const now = Date.now();
    if (Number.isNaN(startedMs)) {
      errors.push("Submission metadata is invalid.");
    } else {
      if (now - startedMs < 1500) {
        errors.push("Form submitted too quickly.");
      }
      if (now - startedMs > 1000 * 60 * 60 * 24) {
        errors.push("Form session expired. Reload and try again.");
      }
    }
  }

  return { valid: errors.length === 0, spam: false, errors, lead };
}

async function persistLead(record) {
  writeQueue = writeQueue.then(async () => {
    await fsp.mkdir(path.dirname(LEAD_STORE_PATH), { recursive: true });
    await fsp.appendFile(LEAD_STORE_PATH, JSON.stringify(record) + "\n", "utf8");
  });
  return writeQueue;
}

async function notifyWebhook(record) {
  if (!LEAD_WEBHOOK_URL) {
    return { sent: false };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    const headers = {
      "content-type": "application/json"
    };

    if (LEAD_WEBHOOK_TOKEN) {
      headers.authorization = "Bearer " + LEAD_WEBHOOK_TOKEN;
    }

    const response = await fetch(LEAD_WEBHOOK_URL, {
      method: "POST",
      headers,
      body: JSON.stringify({
        event: "investor_lead.created",
        lead: record
      }),
      signal: controller.signal
    });

    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new Error("Webhook rejected lead notification: " + response.status + " " + body.slice(0, 220));
    }

    return { sent: true };
  } finally {
    clearTimeout(timeout);
  }
}

function setSecurityHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "font-src 'self' data:",
      "img-src 'self' https: data:",
      "connect-src 'self'",
      "object-src 'none'",
      "base-uri 'self'",
      "frame-ancestors 'none'",
      "form-action 'self' mailto:"
    ].join("; ")
  );
}

function setCorsHeaders(req, res) {
  const origin = req.headers.origin;
  if (!origin || ALLOWED_ORIGINS.size === 0) {
    return;
  }

  if (ALLOWED_ORIGINS.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    res.setHeader("Vary", "Origin");
  }
}

function sendJson(req, res, status, payload, extraHeaders) {
  setSecurityHeaders(res);
  setCorsHeaders(req, res);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    ...extraHeaders
  });
  res.end(JSON.stringify(payload));
}

async function serveStatic(req, res, pathname) {
  const cleanPathname = pathname === "/" ? "/index.html" : pathname;
  const decodedPath = decodeURIComponent(cleanPathname);

  if (decodedPath.includes("\0")) {
    sendJson(req, res, 400, { ok: false, message: "Invalid path" });
    return;
  }

  const safePath = path
    .normalize(decodedPath)
    .replace(/^[/\\]+/, "")
    .replace(/^([.][.][/\\])+/, "");
  let filePath = path.join(PUBLIC_DIR, safePath);

  if (!filePath.startsWith(PUBLIC_DIR)) {
    sendJson(req, res, 403, { ok: false, message: "Forbidden" });
    return;
  }

  let stat;
  try {
    stat = await fsp.stat(filePath);
  } catch {
    sendJson(req, res, 404, { ok: false, message: "Not found" });
    return;
  }

  if (stat.isDirectory()) {
    filePath = path.join(filePath, "index.html");
  }

  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || "application/octet-stream";

  setSecurityHeaders(res);
  res.writeHead(200, {
    "Content-Type": contentType,
    "Cache-Control": ext === ".html" ? "no-cache" : "public, max-age=3600"
  });

  fs.createReadStream(filePath)
    .on("error", () => {
      if (!res.headersSent) {
        sendJson(req, res, 500, { ok: false, message: "Unable to read file" });
      }
    })
    .pipe(res);
}

async function handleLeadPost(req, res) {
  const clientIp = getClientIp(req);
  const limiter = getRateLimit(clientIp);

  if (limiter.limited) {
    sendJson(
      req,
      res,
      limiter.status,
      {
        ok: false,
        message: limiter.message
      },
      { "Retry-After": String(limiter.retryAfterSeconds || 60) }
    );
    return;
  }

  let rawBody;
  try {
    rawBody = await readBody(req, LEAD_MAX_BODY_BYTES);
  } catch (error) {
    sendJson(req, res, error.status || 400, {
      ok: false,
      message: error.message || "Invalid request body"
    });
    return;
  }

  let payload;
  try {
    payload = parseBody(req, rawBody);
  } catch (error) {
    sendJson(req, res, error.status || 400, {
      ok: false,
      message: error.message || "Invalid payload"
    });
    return;
  }

  const validated = validateLead(payload);
  if (validated.spam) {
    sendJson(req, res, 200, {
      ok: true,
      message: "Submission received"
    });
    return;
  }

  if (!validated.valid) {
    sendJson(req, res, 422, {
      ok: false,
      message: validated.errors[0] || "Validation failed",
      errors: validated.errors
    });
    return;
  }

  const leadId = "lead_" + Date.now().toString(36) + "_" + crypto.randomBytes(4).toString("hex");
  const record = {
    id: leadId,
    createdAt: nowIso(),
    lead: validated.lead,
    meta: {
      ipHash: hashValue(clientIp),
      userAgent: normalize(req.headers["user-agent"]),
      referer: normalize(req.headers.referer)
    }
  };

  try {
    await persistLead(record);
  } catch (error) {
    console.error("Lead persistence failure", error);
    sendJson(req, res, 500, {
      ok: false,
      message: "Unable to store request right now"
    });
    return;
  }

  let webhook = { sent: false };
  try {
    webhook = await notifyWebhook(record);
  } catch (error) {
    console.error("Lead webhook failure", error.message);
  }

  sendJson(req, res, 201, {
    ok: true,
    id: leadId,
    message: "Lead request captured",
    webhook: webhook.sent ? "sent" : "not_configured_or_failed"
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const base = "http://" + (req.headers.host || "localhost");
    const requestUrl = new URL(req.url || "/", base);
    const pathname = requestUrl.pathname;

    if (pathname === "/api/leads/health" && req.method === "GET") {
      sendJson(req, res, 200, {
        ok: true,
        service: "aethelred-leads",
        uptimeSeconds: Math.round(process.uptime()),
        timestamp: nowIso()
      });
      return;
    }

    if (pathname === "/api/leads" && req.method === "OPTIONS") {
      setSecurityHeaders(res);
      setCorsHeaders(req, res);
      res.writeHead(204);
      res.end();
      return;
    }

    if (pathname === "/api/leads" && req.method === "POST") {
      await handleLeadPost(req, res);
      return;
    }

    if (req.method === "GET" || req.method === "HEAD") {
      await serveStatic(req, res, pathname);
      return;
    }

    sendJson(req, res, 405, {
      ok: false,
      message: "Method not allowed"
    });
  } catch (error) {
    console.error("Unhandled server error", error);
    if (!res.headersSent) {
      sendJson(req, res, 500, {
        ok: false,
        message: "Internal server error"
      });
    } else {
      res.end();
    }
  }
});

setInterval(() => {
  const now = Date.now();
  const currentDay = new Date(now).toISOString().slice(0, 10);
  for (const [ip, bucket] of rateLimiter.entries()) {
    bucket.windowHits = bucket.windowHits.filter((ts) => now - ts < LEAD_RATE_WINDOW_MS);
    if (bucket.dayKey !== currentDay && !bucket.windowHits.length) {
      rateLimiter.delete(ip);
    }
  }
}, 15 * 60 * 1000).unref();

server.listen(PORT, HOST, () => {
  console.log(`[aethelred] website + lead backend running on http://${HOST}:${PORT}`);
  console.log(`[aethelred] serving static from ${PUBLIC_DIR}`);
  console.log(`[aethelred] lead store: ${LEAD_STORE_PATH}`);
  if (LEAD_WEBHOOK_URL) {
    console.log("[aethelred] webhook notifications: enabled");
  }
});

// PhotonPay static IP relay.
// Runs on a small VPS with a fixed IPv4 address. The NestJS API forwards calls
// here, this server forwards them to PhotonPay, so PhotonPay always sees the
// allowlisted address. Node 20 or newer, no dependencies.
//
//   RELAY_SECRET=... PORT=8787 node server.mjs
import http from "node:http";
import { timingSafeEqual } from "node:crypto";

const PORT = Number(process.env.PORT || 8787);
const SECRET = String(process.env.RELAY_SECRET || "");
const VERSION = "1.1.0";
const ALLOWED_HOSTS = new Set(["x-api.photonpay.com", "x-api.sandbox.photontech.cc"]);
// Only the headers a PhotonPay call needs cross the relay. Nothing else is kept.
const FORWARDED_HEADERS = ["authorization", "content-type", "x-pd-token", "x-pd-sign", "x-pd-authorization"];
// ID photos for cardholder registration reach ~6 MB; Base64 adds a third.
const MAX_BODY = 9 * 1024 * 1024;

function send(res, status, payload) {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify(payload));
}

function authorized(req) {
  if (!SECRET) return false;
  const given = Buffer.from(String(req.headers["x-relay-secret"] || ""));
  const expected = Buffer.from(SECRET);
  return given.length === expected.length && timingSafeEqual(given, expected);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(new Error("Request body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

async function outboundIp() {
  try {
    const res = await fetch("https://checkip.amazonaws.com", { signal: AbortSignal.timeout(8000) });
    return (await res.text()).trim();
  } catch {
    return "";
  }
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || "/", "http://relay.local");

    if (req.method !== "POST" || url.pathname !== "/forward") {
      if (req.method === "GET" && url.pathname === "/health" && authorized(req)) {
        return send(res, 200, { ok: true, version: VERSION, configured: Boolean(SECRET), outbound_ip: await outboundIp() });
      }
      return send(res, 404, { error: "Not found" });
    }
    if (!authorized(req)) {
      return send(res, 401, { error: "Unauthorized" });
    }

    let request;
    try {
      request = JSON.parse(await readBody(req));
    } catch {
      return send(res, 400, { error: "Invalid request body" });
    }

    const target = new URL(String(request.url || ""));
    if (target.protocol !== "https:" || !ALLOWED_HOSTS.has(target.hostname)) {
      return send(res, 400, { error: "Target host is not allowed" });
    }

    // HTTP header names are case-insensitive: match the allowlist without regard
    // to case, and copy each value exactly as received.
    const incoming = {};
    if (request.headers && typeof request.headers === "object" && !Array.isArray(request.headers)) {
      for (const [key, value] of Object.entries(request.headers)) incoming[key.toLowerCase()] = value;
    }
    const headers = {};
    for (const name of FORWARDED_HEADERS) {
      const value = incoming[name];
      if (typeof value === "string" && value) headers[name] = value;
    }

    const method = String(request.method || "GET").toUpperCase();
    // Binary bodies (file uploads) arrive Base64-encoded in body_base64 and are
    // forwarded byte for byte; text bodies arrive in body as before.
    let outbound;
    if (method !== "GET") {
      if (typeof request.body_base64 === "string") outbound = Buffer.from(request.body_base64, "base64");
      else if (request.body != null) outbound = String(request.body);
    }
    const upstream = await fetch(target, {
      method,
      headers,
      body: outbound,
      signal: AbortSignal.timeout(25000),
    });
    const body = await upstream.text();

    return send(res, 200, {
      status: upstream.status,
      headers: {
        "content-type": upstream.headers.get("content-type") || "application/json",
        "cf-ray": upstream.headers.get("cf-ray") || "",
        "x-request-id": upstream.headers.get("x-request-id") || "",
        "x-trace-id": upstream.headers.get("x-trace-id") || "",
      },
      body,
    });
  } catch (error) {
    const timeout = error?.name === "TimeoutError";
    return send(res, 502, { error: timeout ? "PhotonPay did not respond in time" : "Relay could not complete the request" });
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`PhotonPay static IP relay ${VERSION} listening on port ${PORT}`);
});

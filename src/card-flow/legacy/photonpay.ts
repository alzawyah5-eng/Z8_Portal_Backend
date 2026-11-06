// @ts-nocheck
import { readFileSync } from 'node:fs';
import path from 'node:path';
const secrets = { get: (name) => process.env[name] || '' };

const HOSTS = {
  prod: "https://x-api.photonpay.com",
  sandbox: "https://x-api.sandbox.photontech.cc",
};

// Per-instance copy of the shared token. The record in PhotonPayToken is the
// source of truth: PhotonPay invalidates the previous token whenever a new one
// is issued, so every function instance must reuse the same one.
const tokenMemo = new Map();
const TOKEN_REFRESH_MARGIN_MS = 5 * 60 * 1000;
const LOG_BODY_LIMIT = 20000;

// Read on every request, never cached, so rotated credentials take effect
// without restarting the functions.
function readSecret(name) {
  try {
    return String(secrets.get(name) || "").trim();
  } catch {
    return "";
  }
}

function readPrivateSigningKey() {
  const inline = readSecret('PHOTONPAY_RSA_PRIVATE_KEY');
  if (inline) return inline;
  const configuredPath = readSecret('PHOTONPAY_RSA_PRIVATE_KEY_PATH');
  if (!configuredPath) return '';
  try {
    const absolutePath = path.isAbsolute(configuredPath)
      ? configuredPath
      : path.resolve(process.cwd(), configuredPath);
    return readFileSync(absolutePath, 'utf8').trim();
  } catch {
    return '';
  }
}

// Pass the request's local context so the token store and the request log are
// available. Without it calls still work, but nothing is shared or logged.
export function getConfig(context = null) {
  const appId = readSecret("PHOTONPAY_APP_ID");
  const appSecret = readSecret("PHOTONPAY_APP_SECRET");
  const envRaw = readSecret("PHOTONPAY_ENV").toLowerCase();
  const env = envRaw === "prod" || envRaw === "production" || envRaw === "live" ? "prod" : "sandbox";
  const privateKey = readPrivateSigningKey();
  const providerPublicKey = readSecret("PHOTONPAY_PUBLIC_KEY");
  return { appId, appSecret, masterAccountEmail: readSecret("PHOTONPAY_MASTER_ACCOUNT_EMAIL").toLowerCase(), env, envExplicit: Boolean(envRaw), privateKey, providerPublicKey, configured: Boolean(appId && appSecret), context, source: "" };
}

export function host(env) {
  return HOSTS[env] || HOSTS.sandbox;
}

const RELAY_TARGETS = new Set(["x-api.photonpay.com", "x-api.sandbox.photontech.cc"]);

// PhotonPay can restrict API access to an allowlisted IPv4 address. When a
// relay is configured, every provider call goes through it so the provider
// always sees that one fixed address. Without it calls go out directly.
export function getRelayConfig() {
  const base = readSecret("PHOTONPAY_RELAY_URL").replace(/\/+$/, "");
  const secret = readSecret("PHOTONPAY_RELAY_SECRET");
  const valid = /^https:\/\/[^\s/]+(\/\S*)?$/.test(base);
  return { url: valid ? base : "", secret, configured: Boolean(valid && secret) };
}

export async function relayHealth() {
  const relay = getRelayConfig();
  if (!relay.configured) return { configured: false };
  let hostname = "";
  try { hostname = new URL(relay.url).host; } catch { return { configured: false }; }
  try {
    const res = await fetch(`${relay.url}/health`, {
      headers: { "x-relay-secret": relay.secret },
      signal: AbortSignal.timeout(12000),
    });
    const json = await res.json().catch(() => ({}));
    return { configured: true, host: hostname, reachable: res.ok, version: String(json.version || ""), outbound_ip: String(json.outbound_ip || "") };
  } catch (error) {
    return { configured: true, host: hostname, reachable: false, error: String(error?.message || "Relay unreachable").slice(0, 200) };
  }
}

export async function providerFetch(url, init = {}) {
  const relay = getRelayConfig();
  if (!relay.configured) return fetch(url, init);
  const target = new URL(String(url));
  if (!RELAY_TARGETS.has(target.hostname)) throw new Error("Unsupported PhotonPay host");
  const res = await fetch(`${relay.url}/forward`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-relay-secret": relay.secret },
    body: JSON.stringify({
      url: target.toString(),
      method: init.method || "GET",
      headers: init.headers || {},
      ...(init.bodyBase64 ? { body_base64: init.bodyBase64 } : { body: init.body ?? null }),
    }),
    signal: AbortSignal.timeout(30000),
  });
  const payload = await res.json().catch(() => null);
  if (!res.ok || !payload) {
    throw Object.assign(new Error(payload?.error || `Static IP relay failed (HTTP ${res.status})`), { stage: "relay", httpStatus: res.status });
  }
  const forwarded = {};
  for (const name of ["content-type", "cf-ray", "x-request-id", "x-trace-id"]) {
    const value = payload.headers?.[name];
    if (value) forwarded[name] = value;
  }
  return new Response(payload.body || null, { status: Number(payload.status) || 502, headers: forwarded });
}

// ---------------------------------------------------------------------------
// Request log (PhotonPay acceptance item 5). Card numbers, CVVs, expiry dates,
// tokens and credentials are masked before anything is written.
// ---------------------------------------------------------------------------

const SECRET_KEYS = new Set(['cvv', 'cvv2', 'cvc', 'pin', 'token', 'refreshtoken', 'accesstoken', 'idtoken', 'appsecret', 'privatekey', 'password', 'authorization', 'xpdtoken', 'xpdsign', 'signature', 'secret', 'apikey']);
const ID_NUMBER_KEYS = new Set(['certid', 'idnumber', 'passportno', 'passportnumber', 'nationalid', 'identitynumber', 'documentnumber']);
const CARD_NUMBER_KEYS = new Set(['cardno', 'cardnumber', 'pan', 'primaryaccountnumber']);
const EXPIRY_KEYS = new Set(['expirydate', 'expirationdate', 'expiry', 'expdate']);
const PERSONAL_KEYS = new Set(['name', 'fullname', 'firstname', 'lastname', 'cardholdername', 'customername', 'email', 'phone', 'mobile', 'mobileprefix', 'dateofbirth', 'dob', 'birthday', 'nationality', 'address', 'addressline', 'city', 'state', 'postalcode', 'postcode', 'zipcode', 'country', 'reviewreason', 'message', 'msg', 'error', 'reason', 'description']);
const PERSONAL_KEY_PATTERN = /email|phone|mobile|name|birth|nationality|address|postal|postcode|zipcode|reviewreason|document|passport|certificate|portrait|frontphoto|backphoto|frontimage|backimage/i;

function normalizedLogKey(key) {
  return String(key).toLowerCase().replace(/[^a-z0-9]/g, '');
}

function redactText(value) {
  return String(value)
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, '[redacted email]')
    .replace(/\b\d[\d -]{11,20}\d\b/g, '[redacted number]');
}

export function maskIdNumber(value) {
  const text = String(value || "");
  return text.length > 4 ? `${"*".repeat(Math.min(text.length - 4, 12))}${text.slice(-4)}` : "****";
}

function maskCardNumber(value) {
  const digits = String(value || "").replace(/\D/g, "");
  return digits.length >= 10 ? `${digits.slice(0, 6)}******${digits.slice(-4)}` : "***";
}

function redactValue(value, key = "") {
  if (value === null || value === undefined) return value;
  const normalizedKey = normalizedLogKey(key);
  if (SECRET_KEYS.has(normalizedKey) || EXPIRY_KEYS.has(normalizedKey) || ID_NUMBER_KEYS.has(normalizedKey) || PERSONAL_KEYS.has(normalizedKey)
    || PERSONAL_KEY_PATTERN.test(normalizedKey)) return "***";
  if (CARD_NUMBER_KEYS.has(normalizedKey)) return maskCardNumber(value);
  if (Array.isArray(value)) return value.map((item) => redactValue(item));
  if (typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, redactValue(v, k)]));
  }
  // Catch full card numbers that appear outside a named field.
  return typeof value === "string" ? redactText(value).replace(/\b\d{13,19}\b/g, maskCardNumber) : value;
}

export function redactBody(text) {
  if (text === undefined || text === null || text === "") return "";
  let out;
  try {
    out = JSON.stringify(redactValue(JSON.parse(String(text))));
  } catch {
    out = "[non-JSON provider body omitted]";
  }
  return out.length > LOG_BODY_LIMIT ? `${out.slice(0, LOG_BODY_LIMIT)}…[truncated]` : out;
}

export function redactHeaders(headers) {
  const entries = headers instanceof Headers ? [...headers.entries()] : Object.entries(headers || {});
  const out = {};
  for (const [name, raw] of entries) {
    const value = String(raw ?? "");
    const lower = name.toLowerCase();
    if (lower === "authorization") out[name] = `${value.split(" ")[0] || ""} ***`;
    else if (["x-pd-token", "x-pd-sign", "signature"].includes(lower)) out[name] = value ? "***" : "";
    // Any other credential-bearing header is never stored.
    else if (/authorization|token|secret|cookie|api[-_]?key|password|signature|^sign$/.test(lower)) out[name] = "***";
    else out[name] = value.slice(0, 2000);
  }
  return JSON.stringify(out);
}

export async function writeLog(cfg, entry) {
  const context = cfg?.context;
  if (!context) return;
  try {
    await context.entities.PhotonPayLog.create({
      source: cfg.source || "",
      environment: cfg.env || "",
      ...entry,
    });
  } catch (error) {
    // Logging must never break a payment operation.
    console.log("PhotonPay log write failed; database error details omitted.");
  }
}

// Calls PhotonPay and stores only redacted request/response diagnostics.
async function loggedFetch(cfg, url, init) {
  const startedAt = new Date();
  const target = new URL(String(url));
  const entry = {
    kind: "outbound",
    method: init.method || "GET",
    path: target.pathname,
    host: target.host,
    request_headers: redactHeaders(init.headers || {}),
    request_body: redactBody(init.body),
    started_at: startedAt.toISOString(),
  };
  try {
    const res = await providerFetch(url, init);
    const text = await res.text().catch(() => "");
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch { json = null; }
    await writeLog(cfg, {
      ...entry,
      http_status: res.status,
      provider_code: String(json?.code ?? ""),
      response_headers: redactHeaders(res.headers),
      response_body: redactBody(text),
      finished_at: new Date().toISOString(),
      duration_ms: Date.now() - startedAt.getTime(),
    });
    return { res, json: json || {} };
  } catch (error) {
    await writeLog(cfg, {
      ...entry,
      error: "Provider request failed; detailed error omitted from persistent logs.",
      finished_at: new Date().toISOString(),
      duration_ms: Date.now() - startedAt.getTime(),
    });
    throw error;
  }
}

// ---------------------------------------------------------------------------
// Shared access token (PhotonPay acceptance item 4).
// ---------------------------------------------------------------------------

function tokenKey(cfg) {
  return `${cfg.env}:${cfg.appId}`;
}

async function readStoredToken(cfg) {
  if (!cfg.context) return null;
  try {
    const page = await cfg.context.entities.PhotonPayToken.filter({ key: tokenKey(cfg) }, { limit: 1 });
    return (Array.isArray(page) ? page : page.items || [])[0] || null;
  } catch (error) {
    console.log("PhotonPay token store read failed:", error.message);
    return null;
  }
}

async function storeToken(cfg, token, expiresAt, existing) {
  tokenMemo.set(tokenKey(cfg), { token, expiresAt });
  if (!cfg.context) return;
  const data = { key: tokenKey(cfg), token, expires_at: expiresAt, issued_at: new Date().toISOString() };
  try {
    const store = cfg.context.entities.PhotonPayToken;
    if (existing?.id) await store.update(existing.id, data);
    else await store.create(data);
  } catch (error) {
    console.log("PhotonPay token store write failed:", error.message);
  }
}

function expiryFrom(value) {
  const n = Number(value) || 0;
  if (n > 1e12) return n; // epoch milliseconds, as PhotonPay documents
  if (n > 1e9) return n * 1000; // epoch seconds
  if (n > 0) return Date.now() + n * 1000; // seconds from now
  return Date.now() + 2 * 60 * 60 * 1000; // documented 2-hour lifetime
}

// Records a token obtained outside getAccessToken (for example by the
// diagnostics probe), so the rest of the app moves onto it instead of
// sending the one PhotonPay just invalidated.
export async function rememberToken(cfg, data) {
  if (!data?.token) return;
  await storeToken(cfg, data.token, expiryFrom(data.expiresIn), await readStoredToken(cfg));
}

// Returns a valid token, reusing the shared one until 5 minutes before it
// expires. `rejected` is a token PhotonPay just refused: it is never reused.
export async function getAccessToken(cfg, { rejected = "" } = {}) {
  const now = Date.now();
  const memo = tokenMemo.get(tokenKey(cfg));
  if (memo && memo.token !== rejected && memo.expiresAt > now + TOKEN_REFRESH_MARGIN_MS) return memo.token;

  const stored = await readStoredToken(cfg);
  if (stored?.token && stored.token !== rejected && Number(stored.expires_at) > now + TOKEN_REFRESH_MARGIN_MS) {
    tokenMemo.set(tokenKey(cfg), { token: stored.token, expiresAt: Number(stored.expires_at) });
    return stored.token;
  }

  const { res, json } = await loggedFetch(cfg, `${host(cfg.env)}/oauth2/token/accessToken`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      Authorization: `basic ${btoa(`${cfg.appId}/${cfg.appSecret}`)}`,
    },
    signal: AbortSignal.timeout(15000),
  });
  const token = json && json.data ? json.data.token : "";
  if (!res.ok || !token) {
    throw Object.assign(new Error((json && json.msg) || `PhotonPay authorization failed (HTTP ${res.status})`), {
      providerCode: json?.code || "", httpStatus: res.status, stage: "authentication",
      reference: res.headers.get("cf-ray") || res.headers.get("x-request-id") || "",
    });
  }
  await storeToken(cfg, token, expiryFrom(json.data.expiresIn), stored);
  return token;
}

// Only a refusal of the token itself (code 1002 "invalid token") justifies a
// new one. PhotonPay also answers HTTP 401 for API-permission refusals such as
// union-oauth2-self:29509; refreshing then would only invalidate the token
// other requests are using.
function tokenRejected(_res, json) {
  const code = String(json?.code ?? "0000");
  return code !== "0000" && (code === "1002" || /token/i.test(String(json?.msg || "")));
}

function signingError(message) {
  return Object.assign(new Error(message), { stage: "signing" });
}

// Loads PHOTONPAY_RSA_PRIVATE_KEY however it was pasted: full PEM, PEM whose
// line breaks became spaces or literal \n, or the bare Base64 body (PKCS#8, as
// PhotonPay requires, or PKCS#1). Errors name the problem, never the key.
export async function loadPrivateKey(value) {
  const { createPrivateKey, createPublicKey } = await import("node:crypto");
  const raw = String(value || "").replace(/\\n/g, "\n").trim().replace(/^["']+|["']+$/g, "");
  if (!raw) throw signingError("PHOTONPAY_RSA_PRIVATE_KEY is not set, so POST requests cannot be signed.");
  const match = raw.match(/-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END [A-Z0-9 ]+-----/);
  const label = match ? match[1].trim() : "";
  if (/PUBLIC/.test(label)) {
    throw signingError("PHOTONPAY_RSA_PRIVATE_KEY holds a public key. It must hold your private key; the public key goes in the PhotonPay portal.");
  }
  if (/ENCRYPTED/.test(label) || /Proc-Type: 4,ENCRYPTED/.test(raw)) {
    throw signingError("PHOTONPAY_RSA_PRIVATE_KEY is protected by a passphrase. Export it without one (openssl pkey -in key.pem -out plain.pem) and paste that.");
  }
  if (/OPENSSH/.test(label)) {
    throw signingError("PHOTONPAY_RSA_PRIVATE_KEY is an OpenSSH key (from ssh-keygen). Generate a PKCS#8 key with openssl genpkey instead.");
  }
  if (/PuTTY-User-Key-File/.test(raw)) {
    throw signingError("PHOTONPAY_RSA_PRIVATE_KEY is a PuTTY (.ppk) key. Generate a PKCS#8 key with openssl genpkey instead.");
  }
  if (label && !/PRIVATE KEY/.test(label)) {
    throw signingError(`PHOTONPAY_RSA_PRIVATE_KEY contains a "${label.slice(0, 40)}" block, not a private key.`);
  }
  const body = (match ? match[2] : raw).replace(/[^A-Za-z0-9+/=]/g, "");
  const lines = body.match(/.{1,64}/g) || [];
  const wrap = (kind) => `-----BEGIN ${kind}-----\n${lines.join("\n")}\n-----END ${kind}-----\n`;
  for (const kind of label ? [label] : ["PRIVATE KEY", "RSA PRIVATE KEY"]) {
    try {
      const key = createPrivateKey(wrap(kind));
      if (key.asymmetricKeyType !== "rsa") throw signingError(`PHOTONPAY_RSA_PRIVATE_KEY is a ${key.asymmetricKeyType} key; PhotonPay needs an RSA key.`);
      return key;
    } catch (error) {
      if (error.stage === "signing") throw error;
    }
  }
  try {
    createPublicKey(wrap("PUBLIC KEY"));
    throw signingError("PHOTONPAY_RSA_PRIVATE_KEY holds a public key. It must hold your private key; the public key goes in the PhotonPay portal.");
  } catch (error) {
    if (error.stage === "signing") throw error;
  }
  // Describe the shape only (never the content) so the cause can be found.
  const shape = [
    match ? `has a "${label}" header` : "has no BEGIN/END lines",
    `${body.length} key characters (a 1024-bit private key has about 840, a 2048-bit one about 1620)`,
  ].join(", ");
  throw signingError(`PHOTONPAY_RSA_PRIVATE_KEY could not be read as an RSA private key: it ${shape}. Paste the whole private key file, including its BEGIN and END lines.`);
}

// MD5withRSA over the exact JSON body, Base64-encoded (PhotonPay "Signature
// file"). A request is never sent unsigned: failures stop it with a reason.
export async function signBody(bodyString, privateKey) {
  const key = await loadPrivateKey(privateKey);
  const { createSign } = await import("node:crypto");
  const signer = createSign("RSA-MD5");
  signer.update(bodyString, "utf8");
  signer.end();
  return signer.sign(key, "base64");
}

export async function resolveConfig(cfg) {
  if (!cfg.configured) return cfg;
  const other = cfg.env === "sandbox" ? "prod" : "sandbox";
  const order = cfg.envExplicit ? [cfg.env] : [cfg.env, other];
  let lastError;
  for (const env of order) {
    try {
      await getAccessToken({ ...cfg, env });
      return { ...cfg, env };
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError || new Error("PhotonPay authorization failed");
}

export async function photonRequest(cfg, path, options = {}) {
  const method = options.method || "GET";
  const token = await getAccessToken(cfg);
  const url = new URL(`${host(cfg.env)}${path}`);
  if (options.query) {
    Object.entries(options.query).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== "") {
        url.searchParams.set(key, String(value));
      }
    });
  }

  const headers = { "content-type": "application/json", "X-PD-TOKEN": token };
  let bodyString;
  if (method !== "GET" && options.body) {
    bodyString = JSON.stringify(options.body);
    try {
      headers["X-PD-SIGN"] = await signBody(bodyString, cfg.privateKey);
    } catch (error) {
      await writeLog(cfg, {
        kind: "outbound", method, path: url.pathname, host: url.host,
        request_body: redactBody(bodyString), started_at: new Date().toISOString(),
        error: `Not sent: ${error.message}`,
      });
      throw error.stage ? error : signingError(`Request signing failed: ${error.message}`);
    }
  }

  const send = () => loggedFetch(cfg, url.toString(), {
    method,
    headers: { ...headers },
    body: bodyString,
    signal: AbortSignal.timeout(20000),
  });
  let { res, json } = await send();
  // Another instance may have replaced the token since we read it. Pick up the
  // newer one (or fetch a fresh one) and retry exactly once.
  if (tokenRejected(res, json)) {
    headers["X-PD-TOKEN"] = await getAccessToken(cfg, { rejected: token });
    ({ res, json } = await send());
  }

  if (!res.ok) {
    // PhotonPay returns the reason in msg and the precise reason code in code;
    // keep both, because support needs the code to enable an API.
    const message = (json && json.msg) || `PhotonPay request failed (HTTP ${res.status})`;
    throw Object.assign(new Error(json?.code && !message.includes(json.code) ? `${message} (code ${json.code})` : message), {
      providerCode: json?.code || "", httpStatus: res.status, stage: "provider",
    });
  }
  if (json && json.code && json.code !== "0000") {
    throw new Error(`${json.msg || "PhotonPay declined the request"} (code ${json.code})`);
  }
  return json || {};
}

// ---------------------------------------------------------------------------
// File upload (multipart/form-data) for documents such as cardholder ID photos:
// POST /file/apiUpload/{businessKey} returns a file key in data.
// ---------------------------------------------------------------------------

function versionAtLeast(version, minimum) {
  const a = String(version || "0").split(".").map((part) => Number(part) || 0);
  const b = minimum.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if ((a[i] || 0) !== b[i]) return (a[i] || 0) > b[i];
  }
  return true;
}

export async function photonUpload(cfg, businessKey, bytes, fileName, mimeType) {
  const relay = getRelayConfig();
  if (relay.configured) {
    const health = await relayHealth();
    if (!health.reachable) throw Object.assign(new Error("The static IP relay is not reachable, so the file cannot be sent to PhotonPay."), { stage: "relay" });
    if (!versionAtLeast(health.version, "1.1.0")) {
      throw Object.assign(new Error(`The static IP relay (version ${health.version || "unknown"}) cannot forward files. Update relay/server.mjs on the relay server to 1.1.0 and restart it.`), { stage: "relay" });
    }
  }
  const { Buffer } = await import("node:buffer");
  const boundary = `----Z8Upload${crypto.randomUUID().replace(/-/g, "")}`;
  const safeName = String(fileName || "document").replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 80) || "document";
  const payload = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${safeName}"\r\nContent-Type: ${mimeType}\r\n\r\n`, "utf8"),
    Buffer.from(bytes),
    Buffer.from(`\r\n--${boundary}--\r\n`, "utf8"),
  ]);
  const url = `${host(cfg.env)}/file/apiUpload/${encodeURIComponent(businessKey)}`;
  const send = async (token) => {
    const startedAt = new Date();
    const headers = { "content-type": `multipart/form-data; boundary=${boundary}`, "X-PD-TOKEN": token };
    const entry = {
      kind: "outbound", method: "POST", path: new URL(url).pathname, host: new URL(url).host,
      request_headers: redactHeaders(headers),
      // The document itself is never logged, only what was sent.
      request_body: `[file ${safeName}, ${mimeType}, ${bytes.length} bytes]`,
      started_at: startedAt.toISOString(),
    };
    try {
      const res = await providerFetch(url, {
        method: "POST", headers,
        ...(relay.configured ? { bodyBase64: payload.toString("base64") } : { body: payload }),
        signal: AbortSignal.timeout(60000),
      });
      const text = await res.text().catch(() => "");
      let json = {};
      try { json = text ? JSON.parse(text) : {}; } catch { json = {}; }
      await writeLog(cfg, { ...entry, http_status: res.status, provider_code: String(json?.code ?? ""), response_headers: redactHeaders(res.headers), response_body: redactBody(text), finished_at: new Date().toISOString(), duration_ms: Date.now() - startedAt.getTime() });
      return { res, json };
    } catch (error) {
      await writeLog(cfg, { ...entry, error: "Provider file upload failed; detailed error omitted from persistent logs.", finished_at: new Date().toISOString(), duration_ms: Date.now() - startedAt.getTime() });
      throw error;
    }
  };
  const token = await getAccessToken(cfg);
  let { res, json } = await send(token);
  if (tokenRejected(res, json)) ({ res, json } = await send(await getAccessToken(cfg, { rejected: token })));
  if (!res.ok || String(json?.code) !== "0000" || !json?.data) {
    const message = json?.msg || `PhotonPay file upload failed (HTTP ${res.status})`;
    throw Object.assign(new Error(json?.code ? `${message} (code ${json.code})` : message), { providerCode: json?.code || "", httpStatus: res.status, stage: "provider" });
  }
  return String(json.data);
}

// ---------------------------------------------------------------------------
// Card transactions: one mapping shared by the webhook and the daily sync, so
// a transaction looks the same whichever path recorded it.
// ---------------------------------------------------------------------------

function cleanText(value, max = 120) {
  return String(value === undefined || value === null ? "" : value).trim().slice(0, max);
}

function amountOf(value) {
  const n = Number(String(value === undefined || value === null ? "" : value).replace(/[^0-9.-]/g, ""));
  return Number.isFinite(n) ? Math.abs(n) : 0;
}

export function transactionIdOf(body) {
  return cleanText(body.transactionId || body.txnId || body.tradeNo || body.id, 80);
}

export function mapTransaction(body, card, fallbackType = "") {
  const rawStatus = cleanText(body.status || body.txnStatus || body.transactionStatus, 40).toLowerCase();
  const txnType = cleanText(body.transactionType || fallbackType, 40).toLowerCase();
  const declined = ["declined", "failed", "rejected", "denied"].includes(rawStatus);
  // Money moved between the PhotonPay account and the card is not a purchase.
  const topUp = ["recharge", "fund_in"].includes(txnType);
  const fundsReturned = ["recharge_return", "discard_recharge_return"].includes(txnType);
  const reversed = ["reversed", "refunded", "refund", "returned", "void"].includes(rawStatus) ||
    ["refund", "corrective_refund", "void"].includes(txnType);
  const fee = txnType === "service_fee";
  const movement = topUp ? "Card topped up" : fundsReturned ? "Funds returned to account" : "";
  return {
    kind: movement ? "event" : reversed ? "refund" : fee ? "fee" : "spend",
    ...(movement ? { event: movement } : {}),
    photon_txn_id: transactionIdOf(body),
    card_id: card.id,
    card_last4: card.last4,
    card_nickname: card.nickname,
    merchant: movement ? (topUp ? "Top-up from PhotonPay account" : "Returned to PhotonPay account") : cleanText(body.merchantNameLocation || body.merchantName || body.merchant || body.tradeMerchant || body.mcc, 120),
    amount: amountOf(body.transactionAmount ?? body.txnAmount ?? body.amount ?? body.tradeAmount ?? body.settleAmount),
    currency: cleanText(body.transactionCurrency || body.txnCurrency || body.currency || body.tradeCurrency, 3).toUpperCase() || card.currency,
    status: declined ? "declined" : ["pending", "authorized", "processing"].includes(rawStatus) ? "pending" : "completed",
    category: cleanText(body.mcc, 40),
    occurred_at: cleanText(body.createdAt || body.txnDate || body.transactionHappenedAt || body.txnTime || body.transactionTime, 40) || new Date().toISOString(),
    owner_email: card.owner_email || "",
  };
}

// An automatically issued card unlocks for its owner once it is funded: the
// first successful top-up that is not the opening load made at issue (which
// carries the card application's own requestId). Idempotent.
export async function unlockIfFunded(context, card, body = {}) {
  if (!card?.auto_issued || card.funded_at) return false;
  const type = String(body.transactionType || "").toLowerCase();
  const ok = ["succeed", "success", "completed", ""].includes(String(body.status || "").toLowerCase());
  if (body.transactionType !== undefined && !["recharge", "fund_in"].includes(type)) return false;
  if (!ok || (body.requestId && body.requestId === card.request_id)) return false;
  const fresh = await context.entities.Card.get(card.id).catch(() => card);
  if (fresh?.funded_at) return false;
  await context.entities.Card.update(card.id, { funded_at: new Date().toISOString() });
  await context.entities.CardTransaction.create({
    kind: "event", event: "Card details unlocked", card_id: card.id, card_last4: card.last4 || "", card_nickname: card.nickname,
    amount: 0, currency: card.currency || "USD", status: "completed", occurred_at: new Date().toISOString(),
    owner_email: card.owner_email || "", note: "The account was funded; the cardholder can now view the card details.",
  });
  return true;
}

// Creates the transaction, or moves an existing one to its latest status
// (for example pending to completed). Returns what happened.
export async function saveTransaction(context, card, body, fallbackType = "") {
  const data = mapTransaction(body, card, fallbackType);
  if (!data.photon_txn_id) return "skipped";
  const page = await context.entities.CardTransaction.filter({ photon_txn_id: data.photon_txn_id }, { limit: 1 });
  const existing = (Array.isArray(page) ? page : page.items || [])[0];
  if (!existing) {
    await context.entities.CardTransaction.create(data);
    if (data.event === "Card topped up" && data.status === "completed") await unlockIfFunded(context, card, body);
    if (data.status === "declined") {
      await notifyClient(context, card.owner_email, {
        kind: "payment", tone: "warning", title: "A payment was declined",
        body: `${data.merchant ? `${String(data.merchant).slice(0, 60)}: ` : ""}${usdText(Math.abs(Number(data.amount) || 0))} on ${card.nickname || "your card"}${card.last4 ? ` (•••• ${card.last4})` : ""}.`,
        link: `/cards/${card.id}`, key: `declined:${data.photon_txn_id}`,
      });
    }
    return "created";
  }
  if (existing.status !== data.status && existing.status !== "declined") {
    await context.entities.CardTransaction.update(existing.id, { status: data.status });
    return "updated";
  }
  return "unchanged";
}

// ---------------------------------------------------------------------------
// Card issuance via openCardHalo is asynchronous: PhotonPay answers "pending"
// with only the requestId, and the card itself appears later. These helpers
// link a local Card record to the provider card once it exists.
// ---------------------------------------------------------------------------

const CARD_SCHEMES = ["MasterCard", "Discover"];

export function mapCardStatus(status) {
  const value = String(status || "").toLowerCase();
  if (["normal", "active", "activated", "enabled"].includes(value)) return "active";
  if (["frozen", "freeze", "locked", "blocked"].includes(value)) return "frozen";
  if (["cancelled", "canceled", "discarded", "destroyed", "closed", "expired", "lost", "stolen"].includes(value)) return "cancelled";
  return "pending";
}

async function recordEvent(context, record, event, status, note) {
  await context.entities.CardTransaction.create({
    kind: "event", event, card_id: record.id, card_last4: record.last4 || "",
    card_nickname: record.nickname, amount: 0, currency: record.currency,
    status, occurred_at: new Date().toISOString(),
    owner_email: record.owner_email || "", note,
  });
}

// Saves the provider card onto the local record. Only identifiers and the
// last four digits are stored: never the full number, CVV or expiry date.
export async function linkProviderCard(context, record, detail) {
  const card = pickCard(detail);
  if (!card.photon_card_id) return record;
  const update = {
    photon_card_id: card.photon_card_id,
    status: mapCardStatus(card.status),
    ...(Number.isFinite(card.balance) ? { balance: card.balance } : {}),
    ...(card.last4 ? { last4: card.last4, masked_number: card.masked_number } : {}),
    ...(CARD_SCHEMES.includes(card.scheme) ? { scheme: card.scheme } : {}),
  };
  await context.entities.Card.update(record.id, update);
  const linked = { ...record, ...update };
  await recordEvent(context, linked, "Card issued", "completed", "PhotonPay created the card");
  await notifyClient(context, linked.owner_email, { kind: "card", tone: "success", title: "Your card is ready", body: `${linked.nickname || "Your card"}${linked.last4 ? ` (•••• ${linked.last4})` : ""} is ready to use.`, link: `/cards/${linked.id}`, key: `card-ready:${linked.id}` });
  return linked;
}

// Asks PhotonPay how a card application turned out. Returns the record (linked
// when the card exists) and the state: issued, pending, failed or none.
export async function resolveIssuedCard(context, cfg, record) {
  if (!record?.request_id || record.photon_card_id) return { record, state: record?.photon_card_id ? "issued" : "none" };
  const json = await photonRequest(cfg, "/vcc/openApi/v4/getRequestResult", {
    query: { requestId: record.request_id, type: "apply_card" },
  });
  const data = json.data || {};
  const state = String(data.status || data.createCardStatus || "").toLowerCase();
  const detail = data.cardDetail || data.card || null;
  if (detail?.cardId) {
    return { record: await linkProviderCard(context, record, detail), state: "issued" };
  }
  if (["failed", "fail", "rejected"].includes(state)) {
    return { record: await failApplication(context, record, data.code, data.msg), state: "failed" };
  }
  return { record, state: "pending" };
}

// Marks a card application PhotonPay rejected, keeping its code and reason
// (e.g. VCC3040 risk and compliance review) in the card's activity.
export async function failApplication(context, record, code, msg) {
  const reason = [code ? `code ${String(code).slice(0, 20)}` : "", msg ? String(msg).slice(0, 300) : ""].filter(Boolean).join(": ");
  await refundOpening(context, record).catch(() => null);
  if (record.status !== "cancelled") {
    await context.entities.Card.update(record.id, { status: "cancelled", notes: `PhotonPay declined the application${reason ? ` (${reason})` : ""}` });
    await recordEvent(context, record, "Card request declined", "completed",
      `PhotonPay did not create the card${reason ? ` (${reason})` : ""}`);
    await notifyClient(context, record.owner_email, { kind: "card", tone: "warning", title: "Your card couldn't be created", body: "Our card issuer did not create the card. Any money set aside for it goes back to your account.", link: "/cards", key: `card-failed:${record.id}` });
  } else if (reason) {
    await context.entities.Card.update(record.id, { notes: `PhotonPay declined the application (${reason})` });
  }
  return { ...record, status: "cancelled" };
}

// ---------------------------------------------------------------------------
// Client notifications (the bell). Never throws: a notification that cannot
// be written must not undo or fail the action that caused it.
// ---------------------------------------------------------------------------

const usdText = (value) => `${(Math.round((Number(value) || 0) * 100) / 100).toFixed(2)} USD`;

export async function notifyClient(context, email, { kind = "card", tone = "info", title, body = "", link = "", key = "" }) {
  const owner = String(email || "").trim().toLowerCase();
  if (!owner || !title) return null;
  try {
    const db = context.entities;
    if (key) {
      const page = await db.Notification.filter({ owner_email: owner, dedupe_key: key }, { limit: 1 });
      if ((Array.isArray(page) ? page : page?.items || []).length) return null;
    }
    return await db.Notification.create({
      owner_email: owner, kind, tone, title: String(title).slice(0, 120), body: String(body).slice(0, 400),
      link: String(link).slice(0, 200), dedupe_key: key, read: false,
    });
  } catch (error) {
    console.log("Notification not written:", String(error?.message || error).slice(0, 200));
    return null;
  }
}

// A client's PhotonPay verification changed (webhook or sync).
export async function notifyHolderChange(context, before, after) {
  if (!before || before.status === after.status) return;
  const email = before.owner_email || after.owner_email;
  const day = new Date().toISOString().slice(0, 10);
  const key = `holder:${before.id}:${after.status}:${String(after.review_status || "")}:${day}`;
  if (after.status === "active") {
    await notifyClient(context, email, { kind: "verification", tone: "success", title: "You're verified", body: "Your identity is confirmed. Add funds to your account to request your card.", link: "/cards", key });
  } else if (after.status === "suspended") {
    await notifyClient(context, email, { kind: "verification", tone: "warning", title: "Verification not approved", body: "Our card issuer could not confirm your identity. Please contact support.", link: "/verification", key });
  } else if (["modify", "cert_required"].includes(String(after.review_status || "").toLowerCase())) {
    await notifyClient(context, email, { kind: "verification", tone: "warning", title: "More information needed", body: "Our card issuer needs more information to confirm your identity. We'll contact you.", link: "/verification", key });
  }
}

// When PhotonPay does not create a card, the money taken from the client's
// Z8 account for its opening balance goes back to that account (once).
async function refundOpening(context, record) {
  const db = context.entities;
  const page = await db.AccountEntry.filter({ card_id: record.id }, { limit: 20 });
  const rows = Array.isArray(page) ? page : page?.items || [];
  if (rows.some((row) => row.kind === "refund")) return;
  const opened = rows.filter((row) => row.kind === "card_opening" && row.status === "completed");
  const amount = Math.round(-opened.reduce((sum, row) => sum + (Number(row.amount) || 0), 0) * 100) / 100;
  if (!(amount > 0)) return;
  await db.AccountEntry.create({
    owner_email: opened[0].owner_email, client_name: opened[0].client_name || "", kind: "refund", status: "completed",
    amount, currency: "USD", card_id: record.id, card_request_id: opened[0].card_request_id || "",
    note: "Returned to your account: the card could not be created", reported_by: "admin", recorded_by: "system",
    recorded_at: new Date().toISOString(),
  });
  await notifyClient(context, opened[0].owner_email, { kind: "funds", tone: "info", title: "Money returned to your account", body: `${usdText(amount)} is back in your balance because the card could not be created.`, link: "/account", key: `refund:${record.id}` });
}

// Copies PhotonPay's live view of a card (balance, status, limit type) onto the
// local record. Never stores the card number, CVV or expiry.
export async function refreshCardRecord(context, record, detail) {
  const card = pickCard(detail);
  const update = {};
  if (Number.isFinite(card.balance) && card.balance !== record.balance) update.balance = card.balance;
  const status = card.status ? mapCardStatus(card.status) : "";
  if (status && status !== "pending" && status !== record.status) update.status = status;
  const limitType = String(detail?.transactionLimitType || "");
  if (["limited", "unlimited"].includes(limitType) && limitType !== record.transaction_limit_type) update.transaction_limit_type = limitType;
  if (Object.keys(update).length) await context.entities.Card.update(record.id, update);
  return { ...record, ...update };
}

export function pickCard(source) {
  const card = source || {};
  const cardNo = String(card.cardNo || "");
  const digits = cardNo.replace(/\s/g, "");
  return {
    photon_card_id: String(card.cardId || card.cardNo || ""),
    card_no: digits,
    last4: digits.slice(-4),
    masked_number: digits ? `•••• •••• •••• ${digits.slice(-4)}` : "",
    cvv: card.cvv || "",
    scheme: card.cardScheme || "",
    currency: card.cardCurrency || "",
    status: card.cardStatus || "",
    card_type: card.cardType || "",
    form_factor: card.cardFormFactor || "",
    balance: card.cardBalance !== undefined ? Number(card.cardBalance) : null,
    cardholder_id: card.cardholderId || "",
    nickname: card.nickname || "",
    expiry: card.expiryDate || card.expirationDate || "",
  };
}

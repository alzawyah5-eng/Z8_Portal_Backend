// @ts-nocheck
const secrets = { get: (name) => process.env[name] || '' };
import { getConfig, getAccessToken, host, loadPrivateKey, providerFetch, relayHealth, rememberToken, signBody, writeLog } from "./photonpay";

function readSecret(name) {
  try {
    return String(secrets.get(name) || "").trim();
  } catch {
    return "";
  }
}

// SHA-256 of a public key's SPKI DER form: the same fingerprint `openssl pkey
// -pubin -outform DER | sha256sum` gives for the key shown in the portal.
async function publicFingerprint(value) {
  const raw = String(value || "").replace(/\\n/g, "\n").trim();
  if (!raw) return null;
  try {
    const { createPublicKey, createHash } = await import("node:crypto");
    const body = raw.replace(/-----[^-]+-----/g, "").replace(/[^A-Za-z0-9+/=]/g, "");
    const pem = `-----BEGIN PUBLIC KEY-----\n${(body.match(/.{1,64}/g) || []).join("\n")}\n-----END PUBLIC KEY-----`;
    const key = createPublicKey(/BEGIN RSA PUBLIC KEY/.test(raw) ? raw : pem);
    return {
      bits: key.asymmetricKeyDetails?.modulusLength || null,
      sha256: createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex"),
    };
  } catch {
    return "unreadable";
  }
}

export default async function (req, context) {
  if (req.method !== "POST") return Response.json({ error: "Method not allowed" }, { status: 405 });
  try {
    const user = await context.auth.me().catch(error => error.status === 401 ? null : Promise.reject(error));
    if (!user) return Response.json({ error: "Unauthorized" }, { status: 401 });
    if (user.role !== "admin") return Response.json({ error: "Administrator access required" }, { status: 403 });
    const options = await req.json().catch(() => ({}));
    const cfg = { ...getConfig(context), source: "photonpayDiagnostics" };
    // Compare against the portal without returning either credential or its
    // stored hash. This mode makes no network requests.
    if (options.compare_only === true) {
      const portalId = typeof options.portal_app_id === "string" ? options.portal_app_id.trim() : "";
      const portalHash = typeof options.portal_secret_sha256 === "string" ? options.portal_secret_sha256.toLowerCase() : "";
      if (!portalId || portalId.length > 128 || !/^[a-f0-9]{64}$/.test(portalHash)) {
        return Response.json({ error: "A portal App ID and SHA-256 fingerprint are required" }, { status: 400 });
      }
      const { createHash, timingSafeEqual } = await import("node:crypto");
      const actualHash = createHash("sha256").update(cfg.appSecret).digest();
      const expectedHash = Uint8Array.from(portalHash.match(/../g), byte => parseInt(byte, 16));
      return Response.json({
        environment: cfg.env, configured: cfg.configured,
        matches: {
          app_id: Boolean(cfg.appId) && cfg.appId === portalId,
          app_secret: Boolean(cfg.appSecret) && timingSafeEqual(actualHash, expectedHash),
        },
      });
    }
    const encoded = btoa(`${cfg.appId}/${cfg.appSecret}`);
    const redact = (value) => {
      let text = String(value || "");
      for (const secret of [cfg.appId, cfg.appSecret, cfg.privateKey, encoded]) {
        if (secret) text = text.split(secret).join("[redacted]");
      }
      return text.slice(0, 600);
    };
    const quality = (value) => ({
      present: Boolean(value), length: value.length,
      containsWhitespace: /\s/.test(value),
      containsNonAscii: /[^\x20-\x7E]/.test(value),
      wrappedInQuotes: /^["']|["']$/.test(value),
    });
    const result = {
      checked_at: new Date().toISOString(),
      environment: cfg.env, environment_explicit: cfg.envExplicit,
      credentials: { app_id: quality(cfg.appId), app_secret: quality(cfg.appSecret) },
      key: { present: Boolean(cfg.privateKey), valid: false },
      probes: [],
    };
    if (cfg.privateKey) {
      try {
        const { createPublicKey, createSign, createVerify, createHash } = await import("node:crypto");
        // Use the same loader the signing path uses, so this check reports
        // exactly what a real card request will do.
        const key = await loadPrivateKey(cfg.privateKey);
        const publicKey = createPublicKey(key);
        const publicPem = publicKey.export({ type: "spki", format: "pem" });
        const merchantSpkiSha256 = createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
        // PHOTONPAY_PUBLIC_KEY must hold PhotonPay's own key (it verifies their
        // notifications). MERCHANT_PUBLIC_KEY is an optional copy of the key
        // registered in the portal, used only for this comparison.
        const providerKey = await publicFingerprint(cfg.providerPublicKey);
        const savedMerchantKey = await publicFingerprint(readSecret("MERCHANT_PUBLIC_KEY"));
        const sample = JSON.stringify({ purpose: "Z8 signing self-test" });
        const signer = createSign("RSA-MD5"); signer.update(sample); signer.end();
        const signature = signer.sign(key);
        const verifier = createVerify("RSA-MD5"); verifier.update(sample); verifier.end();
        result.key = {
          present: true, valid: true, type: key.asymmetricKeyType,
          bits: key.asymmetricKeyDetails?.modulusLength,
          pkcs8: cfg.privateKey.includes("BEGIN PRIVATE KEY"),
          public_key_sha256: createHash("sha256").update(publicPem).digest("hex"),
          signature_verified: verifier.verify(publicKey, signature),
          // The public half of the saved private key. PhotonPay's portal must
          // hold exactly this key, so administrators can copy it from here.
          public_key_pem: publicPem,
          // PhotonPay validates X-PD-SIGN with the public key registered on the
          // App ID. If the two keys are not a pair every POST returns
          // "invalid sign", so compare them here instead of guessing.
          public_key_spki_sha256: merchantSpkiSha256,
          // Compares with the saved copy of the portal key, when one is saved.
          portal_key_matches: savedMerchantKey && typeof savedMerchantKey === "object"
            ? savedMerchantKey.sha256 === merchantSpkiSha256
            : savedMerchantKey,
        };
        result.photonpay_public_key = providerKey && typeof providerKey === "object"
          ? { ...providerKey, is_merchant_key: providerKey.sha256 === merchantSpkiSha256 }
          : { status: providerKey === null ? "not set" : "unreadable" };
      } catch (error) { result.key.error = redact(error.message); }
    }
    // The relay's own address is the one PhotonPay allowlists, so report it
    // before any provider probe.
    result.relay = await relayHealth();
    // Public network checks never receive merchant credentials. Prefer the
    // provider edge, then use Cloudflare if that API host does not expose trace.
    result.egress = { observed_ip: null };
    for (const traceUrl of [host(cfg.env) + "/cdn-cgi/trace", "https://www.cloudflare.com/cdn-cgi/trace"]) {
      try {
        const trace = await fetch(traceUrl, { signal: AbortSignal.timeout(10000) });
        const fields = Object.fromEntries((await trace.text()).trim().split("\n").filter(line => line.includes("=")).map(line => { const index = line.indexOf("="); return [line.slice(0, index), line.slice(index + 1)]; }));
        if (/^[0-9a-fA-F:.]+$/.test(fields.ip || "")) {
          result.egress = { observed_ip: fields.ip, country: fields.loc || null, edge: fields.colo || null, source: new URL(traceUrl).hostname, observed_at: new Date().toISOString() };
          break;
        }
      } catch { /* Continue to the public fallback without exposing request data. */ }
    }
    try {
      const address = (await (await fetch("https://checkip.amazonaws.com/", { signal: AbortSignal.timeout(10000) })).text()).trim();
      if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(address)) {
        result.egress = { ...result.egress, observed_ip: address, source: "checkip.amazonaws.com", observed_at: new Date().toISOString() };
      }
    } catch { /* Keep the trace result if the independent IPv4 check fails. */ }
    const relayIp = String(result.relay?.outbound_ip || "");
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(relayIp)) {
      result.egress = { observed_ip: relayIp, source: "static_ip_relay", observed_at: new Date().toISOString() };
    }
    if (!cfg.configured || options.egress_only === true) return Response.json(result);
    const probe = async (environment, authMode, scheme = "basic") => {
      const method = authMode === "token" ? "POST" : "GET";
      const path = authMode === "token" ? "/oauth2/token/accessToken" : "/vcc/openApi/v4/getCardBin";
      const headers = { "content-type": "application/json" };
      headers[authMode === "token" ? "Authorization" : "X-PD-AUTHORIZATION"] = scheme + " " + encoded;
      const started = Date.now();
      try {
        const response = await providerFetch(host(environment) + path, { method, headers, signal: AbortSignal.timeout(15000) });
        const body = await response.text();
        let json;
        try { json = JSON.parse(body); } catch { json = null; }
        const success = Boolean(response.ok && json && String(json.code) === "0000" &&
          (authMode !== "token" || json.data?.token));
        const row = {
          environment, auth_mode: authMode, scheme, host: host(environment), path,
          http_status: response.status, code: json?.code ?? null,
          message: redact(json?.msg || (json ? "" : body)),
          provider_request_id: redact(json?.reqId || json?.requestId || json?.traceId || ""),
          success, elapsed_ms: Date.now() - started,
          response_headers: Object.fromEntries(["server", "content-type", "x-request-id", "x-trace-id", "cf-ray"].map(name => [name, response.headers.get(name)]).filter(([, value]) => value)),
        };
        if (authMode === "direct" && success) {
          const data = json.data || json.rows || [];
          row.bin_count = Array.isArray(data) ? data.length : (data.list || []).length;
        }
        result.probes.push(row);
        // Issuing this token just invalidated the shared one, so hand it to
        // the rest of the app rather than leave cards on a dead token.
        if (success && authMode === "token") await rememberToken({ ...cfg, env: environment }, json.data);
        return success;
      } catch (error) {
        result.probes.push({ environment, auth_mode: authMode, scheme, host: host(environment), path, success: false, network_error: redact(error.message), elapsed_ms: Date.now() - started });
        return false;
      }
    };
    const primary = await probe(cfg.env, "token");
    // A token proves the credentials, not card access: PhotonPay still issues
    // tokens to apps whose card APIs are switched off. Probe one read endpoint
    // with that token so this check reports real access, not just sign-in.
    if (primary) {
      const started = Date.now();
      try {
        const token = await getAccessToken(cfg);
        const response = await providerFetch(
          host(cfg.env) + "/vcc/openApi/v4/getCardBin?cardFormFactor=virtual_card",
          { method: "GET", headers: { "content-type": "application/json", "X-PD-TOKEN": token }, signal: AbortSignal.timeout(15000) },
        );
        const json = await response.json().catch(() => ({}));
        result.permission = {
          environment: cfg.env,
          allowed: Boolean(response.ok && String(json?.code) === "0000"),
          http_status: response.status,
          code: json?.code ?? null,
          message: redact(json?.msg || ""),
          elapsed_ms: Date.now() - started,
        };
      } catch (error) {
        result.permission = { environment: cfg.env, allowed: false, network_error: redact(error.message) };
      }
    }
    // A signed POST proves the private key matches what PhotonPay holds. The
    // payload is deliberately invalid (a card that cannot exist), so the only
    // possible refusal is the signature: "invalid sign" (1001) means the keys
    // are not a pair or the digest is wrong; any other code means signing passed.
    // Every candidate digest is tried so the right one is identified, not guessed.
    result.signing = [];
    if (primary) {
      let token = "";
      let key = null;
      try {
        token = await getAccessToken(cfg);
        key = await loadPrivateKey(cfg.privateKey);
      } catch (error) {
        // Report why signing cannot even be attempted instead of failing the
        // whole check, so the administrator sees the real cause.
        result.signing_error = redact(error.message);
      }
      const body = JSON.stringify({ cardId: "Z8-SIGN-PROBE", requestId: "Z8SIGNPROBE", status: "freeze" });
      const { createSign } = await import("node:crypto");
      for (const algorithm of key && token ? ["RSA-MD5", "RSA-SHA256", "RSA-SHA1", "RSA-SHA512", "RSA-SHA384"] : []) {
        const started = Date.now();
        try {
          const signer = createSign(algorithm); signer.update(body, "utf8"); signer.end();
          const response = await providerFetch(host(cfg.env) + "/vcc/openApi/v4/freezeCard", {
            method: "POST",
            headers: { "content-type": "application/json", "X-PD-TOKEN": token, "X-PD-SIGN": signer.sign(key, "base64") },
            body,
            signal: AbortSignal.timeout(15000),
          });
          const json = await response.json().catch(() => ({}));
          const code = String(json?.code ?? "");
          result.signing.push({
            algorithm, http_status: response.status, code: code || null,
            message: redact(json?.msg || ""), signature_accepted: code !== "1001",
            elapsed_ms: Date.now() - started,
          });
        } catch (error) {
          result.signing.push({ algorithm, signature_accepted: false, network_error: redact(error.message) });
        }
      }
    }
    // Same signed request sent straight to PhotonPay instead of through the
    // relay, to tell a key problem apart from the relay mangling the request.
    result.signing_direct = [];
    if (primary) {
      const body = JSON.stringify({ cardId: "Z8-SIGN-PROBE", requestId: "Z8SIGNPROBE", status: "freeze" });
      const { createSign } = await import("node:crypto");
      for (const algorithm of ["RSA-MD5", "RSA-SHA256"]) {
        try {
          const token = await getAccessToken(cfg);
          const signer = createSign(algorithm); signer.update(body, "utf8"); signer.end();
          const response = await fetch(host(cfg.env) + "/vcc/openApi/v4/freezeCard", {
            method: "POST",
            headers: { "content-type": "application/json", "X-PD-TOKEN": token, "X-PD-SIGN": signer.sign(await loadPrivateKey(cfg.privateKey), "base64") },
            body,
            signal: AbortSignal.timeout(15000),
          });
          const json = await response.json().catch(() => ({}));
          const code = String(json?.code ?? "");
          result.signing_direct.push({ algorithm, http_status: response.status, code: code || null, message: redact(json?.msg || ""), signature_accepted: code !== "1001" });
        } catch (error) {
          result.signing_direct.push({ algorithm, signature_accepted: false, network_error: redact(error.message) });
        }
      }
    }
    if (!primary) {
      await probe(cfg.env, "token", "Basic");
      await probe(cfg.env, "direct");
      await probe(cfg.env === "prod" ? "sandbox" : "prod", "token");
    }
    // Keep a copy in the request log so the result can be reviewed later.
    const { public_key_pem: _omit, ...keySummary } = result.key || {};
    await writeLog(cfg, {
      kind: "diagnostic",
      method: "CHECK",
      path: "photonpayDiagnostics",
      started_at: result.checked_at,
      finished_at: new Date().toISOString(),
      response_body: JSON.stringify({ ...result, key: keySummary }).slice(0, 20000),
    });
    return Response.json(result);
  } catch (error) {
    // Never return credentials: messages here are provider text or key-shape
    // descriptions that deliberately exclude the key itself.
    return Response.json({
      error: "Connection diagnostics could not complete",
      detail: String(error?.message || "").slice(0, 300),
    }, { status: 500 });
  }
}

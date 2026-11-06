// @ts-nocheck
const secrets = { get: (name) => process.env[name] || '' };
import { failApplication, getConfig, notifyHolderChange, redactBody, redactHeaders, resolveIssuedCard, saveTransaction, writeLog } from "./photonpay";

const CARD_STATUS = {
  active: "active",
  activated: "active",
  normal: "active",
  frozen: "frozen",
  freeze: "frozen",
  unactivated: "pending",
  pending: "pending",
  cancelled: "cancelled",
  canceled: "cancelled",
  discarded: "cancelled",
  discard: "cancelled",
  lost: "cancelled",
  stolen: "cancelled",
  expired: "cancelled",
};

function readSecret(name) {
  try {
    return String(secrets.get(name) || "").trim();
  } catch {
    return "";
  }
}

function clean(value, max = 120) {
  return String(value === undefined || value === null ? "" : value).trim().slice(0, max);
}

function normalizePem(value) {
  const cleaned = String(value || "").replace(/\\n/g, "\n").trim();
  if (cleaned.includes("BEGIN")) return cleaned;
  const body = cleaned.replace(/\s+/g, "").match(/.{1,64}/g) || [];
  return `-----BEGIN PUBLIC KEY-----\n${body.join("\n")}\n-----END PUBLIC KEY-----`;
}

// Commercial digest first; PhotonPay documents MD5withRSA, kept as the fallback scheme.
const SIGNATURE_ALGORITHMS = ["RSA-SHA256", "RSA-MD5"];

async function signatureValid(rawBody, signature, publicKey) {
  if (!signature) return false;
  try {
    const { createVerify } = await import("node:crypto");
    const pem = normalizePem(publicKey);
    for (const algorithm of SIGNATURE_ALGORITHMS) {
      try {
        const verifier = createVerify(algorithm);
        verifier.update(rawBody, "utf8");
        verifier.end();
        if (verifier.verify(pem, signature, "base64")) return true;
      } catch (error) {
        console.log(`PhotonPay signature check (${algorithm}) failed:`, error.message);
      }
    }
    return false;
  } catch (error) {
    console.log("PhotonPay notification signature check failed:", error.message);
    return false;
  }
}

// Only the provider's own card identifier may select the record a notification writes to.
async function findCard(context, photonCardId) {
  if (!photonCardId) return null;
  const page = await context.entities.Card.filter({ photon_card_id: photonCardId }, { limit: 1 });
  return (Array.isArray(page) ? page : page.items || [])[0] || null;
}

export default async function (req, requestContext) {
  // Every notification is logged with its headers, body and our reply, so
  // PhotonPay support can trace a delivery end to end.
  const startedAt = new Date();
  const context = requestContext;
  let rawBody = "";
  let logCfg = null;
  const respond = async (payload, status = 200, note = "") => {
    if (logCfg) {
      await writeLog(logCfg, {
        kind: "webhook",
        method: req.method,
        path: new URL(req.url).pathname,
        request_headers: redactHeaders(req.headers),
        request_body: redactBody(rawBody),
        started_at: startedAt.toISOString(),
        http_status: status,
        response_body: redactBody(JSON.stringify(payload)),
        finished_at: new Date().toISOString(),
        duration_ms: Date.now() - startedAt.getTime(),
        ...(note ? { error: redactBody(JSON.stringify({ error: note })) } : {}),
      });
    }
    return Response.json(payload, { status });
  };
  try {
    if (req.method !== "POST") return Response.json({ error: "Method not allowed" }, { status: 405, headers: { Allow: "POST" } });

    rawBody = await req.text();
    logCfg = { ...getConfig(context), source: "photonpayWebhook" };
    // Fail closed: without the provider key every notification is rejected, never trusted.
    const publicKey = readSecret("PHOTONPAY_PUBLIC_KEY");
    if (!publicKey) {
      console.log("photonpayWebhook rejected: PHOTONPAY_PUBLIC_KEY is not configured");
      logCfg = null; // Refused before any trust decision: nothing is stored for it.
      return respond({ error: "Notifications are not configured" }, 503, "PHOTONPAY_PUBLIC_KEY is not configured");
    }
    const valid = await signatureValid(rawBody, req.headers.get("X-PD-SIGN") || "", publicKey);
    if (!valid) {
      // Anyone can POST here, so unsigned calls only reach the console: storing
      // a record per rejected request would let a stranger flood the audit log.
      console.log("photonpayWebhook rejected: invalid notification signature");
      logCfg = null;
      return respond({ error: "Invalid notification signature" }, 401, "Signature verification failed");
    }

    const body = JSON.parse(rawBody || "{}");
    const category = clean(req.headers.get("X-PD-NOTIFICATION-CATAGORY") || body.notifyCategory, 40).toLowerCase();
    const type = clean(req.headers.get("X-PD-NOTIFICATION-TYPE") || body.notifyType, 60).toLowerCase();

    // Outcome of an openCardHalo application, matched by its requestId.
    if (type === "issuing_card_issuance_result" || category === "issuing_card_issuance_result") {
      const requestId = clean(body.requestId, 64);
      const page = requestId
        ? await context.entities.Card.filter({ request_id: requestId }, { limit: 1 })
        : [];
      const record = (Array.isArray(page) ? page : page.items || [])[0];
      if (!record) return respond({ roger: true }, 200, `No local card for application ${requestId || "(none)"}`);
      const outcome = clean(body.createCardStatus, 20).toLowerCase();
      if (outcome === "failed") {
        await failApplication(context, record, clean(body.code, 20), clean(body.msg, 300));
      } else if (body.cardId && !record.photon_card_id) {
        try {
          await resolveIssuedCard(context, logCfg, record);
        } catch (error) {
          await context.entities.Card.update(record.id, { photon_card_id: clean(body.cardId, 64) });
          console.log("photonpayWebhook could not fetch the issued card:", error.message);
        }
      }
      return respond({ roger: true });
    }

    if (type === "card_status_update" || (category === "issuing_card" && body.cardId && body.cardStatus)) {
      const nextStatus = CARD_STATUS[clean(body.cardStatus, 30).toLowerCase()];
      let card = await findCard(context, clean(body.cardId, 64));
      // A card applied for with openCardHalo is not linked yet: match it by the
      // application's requestId, then ask PhotonPay for the card it created.
      if (!card && body.requestId) {
        const page = await context.entities.Card.filter({ request_id: clean(body.requestId, 64) }, { limit: 1 });
        const pending = (Array.isArray(page) ? page : page.items || [])[0];
        if (pending && !pending.photon_card_id) {
          try {
            card = (await resolveIssuedCard(context, logCfg, pending)).record;
          } catch (error) {
            console.log("photonpayWebhook could not resolve card application:", error.message);
          }
          if (!card?.photon_card_id && body.cardId) {
            await context.entities.Card.update(pending.id, { photon_card_id: clean(body.cardId, 64) });
            card = { ...pending, photon_card_id: clean(body.cardId, 64) };
          }
        }
      }
      if (card && nextStatus && card.status !== nextStatus) {
        await context.entities.Card.update(card.id, { status: nextStatus });
        await context.entities.CardTransaction.create({
          kind: "event",
          event: `Card status: ${nextStatus}`,
          card_id: card.id,
          card_last4: card.last4,
          card_nickname: card.nickname,
          amount: 0,
          currency: card.currency,
          status: "completed",
          occurred_at: new Date().toISOString(),
          owner_email: card.owner_email || "",
          note: "Reported by the card provider",
        });
      }
      return respond({ roger: true });
    }

    if (type.includes("cardholder") || category === "issuing_cardholder") {
      if (body.cardholderId) {
        const page = await context.entities.Cardholder.filter(
          { photon_cardholder_id: clean(body.cardholderId, 64) }, { limit: 1 },
        );
        const holder = (Array.isArray(page) ? page : page.items || [])[0];
        if (holder) {
          const providerStatus = clean(body.status || holder.provider_status, 30).toLowerCase() || "unknown";
          const reviewStatus = clean(body.cardholderReviewStatus || holder.review_status, 30).toLowerCase() || "unknown";
          // With idInfoRequirement N PhotonPay needs no identity review.
          const noReviewNeeded = clean(body.idInfoRequirement, 2).toUpperCase() === "N" && !["rejected", "modify"].includes(reviewStatus);
          const approved = providerStatus === "normal" && (reviewStatus === "approved" || noReviewNeeded);
          const next = {
            provider_status: providerStatus, review_status: reviewStatus,
            status: approved ? "active" : ["disabled", "rejected"].includes(providerStatus) || reviewStatus === "rejected" ? "suspended" : "pending",
            ...(body.reason !== undefined ? { review_reason: clean(body.reason, 600) } : {}),
            synced_at: new Date().toISOString(),
          };
          await context.entities.Cardholder.update(holder.id, next);
          await notifyHolderChange(context, holder, { ...holder, ...next });
        }
      }
      return respond({ roger: true });
    }

    if (category.startsWith("issuing") || body.txnId || body.transactionId) {
      const card = await findCard(context, clean(body.cardId, 64));
      if (!card) return respond({ roger: true }, 200, "No local card for this cardId");
      const outcome = await saveTransaction(context, card, body, type);
      return respond({ roger: true }, 200, outcome === "skipped" ? "No transaction ID in notification" : "");
    }

    console.log("PhotonPay notification ignored:", category, type);
    return respond({ roger: true }, 200, `Ignored notification ${category}/${type}`);
  } catch (error) {
    console.log("photonpayWebhook error:", error.message);
    // A failure here is reported (not acknowledged) so PhotonPay retries the
    // delivery; the daily transaction sync also back-fills anything missed.
    return respond({ error: "Notification could not be processed" }, 500, String(error?.message || error));
  }
}

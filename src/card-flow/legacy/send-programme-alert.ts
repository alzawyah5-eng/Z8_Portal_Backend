// @ts-nocheck

const TEMPLATES = { status: "CardStatusAlert", declined: "DeclinedTransaction" };
const APP_URL = "https://portal.z8card.com";

function clean(value, max = 200) {
  return String(value === undefined || value === null ? "" : value).trim().slice(0, max);
}

function formatWhen(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

export default async function (req, context) {
  try {
    const user = await context.auth.me().catch((e) => (e.status === 401 ? null : Promise.reject(e)));
    if (!user) return Response.json({ error: "Unauthorized" }, { status: 401 });
    if (user.role !== "admin") return Response.json({ error: "Forbidden" }, { status: 403 });

    const body = await req.json().catch(() => ({}));
    const kind = clean(body.kind, 16);
    const recordId = clean(body.record_id, 64);
    if (!TEMPLATES[kind]) return Response.json({ error: "Unsupported alert" }, { status: 400 });
    if (!recordId) return Response.json({ error: "record_id is required" }, { status: 400 });

    let variables = null;
    if (kind === "status") {
      const card = await context.entities.Card.get(recordId).catch((e) => (e.status === 404 ? null : Promise.reject(e)));
      if (!card) return Response.json({ error: "Card not found" }, { status: 404 });
      variables = {
        card_name: card.nickname || "Z8 card",
        last4: card.last4 || "",
        cardholder: card.cardholder_name || "Not assigned",
        previous_status: clean(body.previous_status, 24) || "unknown",
        new_status: card.status || "unknown",
        card_url: `${APP_URL}/cards/${card.id}`,
      };
    } else {
      const tx = await context.entities.CardTransaction.get(recordId).catch((e) => (e.status === 404 ? null : Promise.reject(e)));
      if (!tx) return Response.json({ error: "Transaction not found" }, { status: 404 });
      variables = {
        merchant: tx.merchant || "Unknown merchant",
        amount: Number.isFinite(Number(tx.amount)) ? Number(tx.amount).toFixed(2) : "0.00",
        currency: tx.currency || "USD",
        card_name: tx.card_nickname || "Z8 card",
        last4: tx.card_last4 || "",
        category: tx.category || "Uncategorised",
        occurred_at: formatWhen(tx.occurred_at) || "Just now",
        card_url: tx.card_id ? `${APP_URL}/cards/${tx.card_id}` : `${APP_URL}/activity`,
      };
    }

    const admins = await context.entities.User.filter({ role: "admin" });
    const rows = Array.isArray(admins) ? admins : admins.items || [];
    const recipients = rows.map((row) => row.email).filter(Boolean).slice(0, 10);
    if (!recipients.length) return Response.json({ sent: 0, recipients: 0 });

    const results = await Promise.allSettled(
      recipients.map((to) =>
        context.mailer.send({
          to,
          template_name: TEMPLATES[kind],
          variables,
          category: "transactional",
        }),
      ),
    );
    const sent = results.filter((result) => result.status === "fulfilled").length;
    if (!sent) return Response.json({ error: "Alert could not be delivered" }, { status: 502 });
    return Response.json({ sent, recipients: recipients.length });
  } catch (error) {
    return Response.json({ error: error.message }, { status: 500 });
  }
}
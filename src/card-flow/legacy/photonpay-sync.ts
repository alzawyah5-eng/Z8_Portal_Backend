// @ts-nocheck
import { getConfig, photonRequest, refreshCardRecord, resolveConfig, resolveIssuedCard, saveTransaction, writeLog } from "./photonpay";

// Daily back-fill of card transactions (PhotonPay acceptance: "24-hour query of
// data from the previous 24 hours"). Webhooks remain the primary source; this
// catches anything a missed or failed notification left out.
//
// PhotonPay's createdAt has no time zone, so the window reaches 48 hours back
// and 12 hours ahead of UTC. Saving is keyed by transaction ID, so overlapping
// runs never create duplicates.
const LOOKBACK_HOURS = 48;
const LOOKAHEAD_HOURS = 12;
const PAGE_SIZE = 100;
const MAX_PAGES = 50;
const LOG_RETENTION_DAYS = 90;
const LOG_CLEANUP_BATCH = 200;

function providerTime(date) {
  return date.toISOString().slice(0, 19);
}

function rowsOf(json) {
  const data = json?.data;
  return Array.isArray(data) ? data : data?.list || data?.rows || [];
}

async function cleanupLogs(context) {
  const cutoff = new Date(Date.now() - LOG_RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString();
  try {
    const page = await context.entities.PhotonPayLog.filter(
      { started_at: { $lt: cutoff } }, { limit: LOG_CLEANUP_BATCH },
    );
    const rows = Array.isArray(page) ? page : page.items || [];
    await Promise.all(rows.map((row) => context.entities.PhotonPayLog.delete(row.id)));
    return rows.length;
  } catch (error) {
    console.log("PhotonPay log cleanup skipped:", error.message);
    return 0;
  }
}

export default async function (req, context) {
  const startedAt = new Date();
  try {
    const user = await context.auth.me().catch((e) => (e.status === 401 ? null : Promise.reject(e)));
    if (!user) return Response.json({ error: "Unauthorized" }, { status: 401 });
    if (user.role !== "admin") return Response.json({ error: "Administrator access required" }, { status: 403 });

    const cfg = { ...getConfig(context), source: "photonpayTransactionSync" };
    if (!cfg.configured) return Response.json({ skipped: true, reason: "PhotonPay is not configured" });
    const live = await resolveConfig(cfg);

    // First link any card applications PhotonPay has finished, so the new
    // cards' transactions below are matched to them.
    const applications = { checked: 0, issued: 0, failed: 0, pending: 0 };
    try {
      const page = await context.entities.Card.filter({ status: "pending" }, { limit: 50 });
      for (const record of (Array.isArray(page) ? page : page.items || [])) {
        if (!record.request_id || record.photon_card_id) continue;
        applications.checked++;
        const { state } = await resolveIssuedCard(context, live, record).catch(() => ({ state: "pending" }));
        if (applications[state] !== undefined) applications[state]++;
      }
    } catch (error) {
      console.log("Card application check skipped:", error.message);
    }

    const from = new Date(Date.now() - LOOKBACK_HOURS * 60 * 60 * 1000);
    const to = new Date(Date.now() + LOOKAHEAD_HOURS * 60 * 60 * 1000);
    const counts = { fetched: 0, created: 0, updated: 0, unchanged: 0, skipped: 0, unknown_card: 0 };
    const cards = new Map();

    let pageIndex = 1;
    let more = true;
    while (more && pageIndex <= MAX_PAGES) {
      const json = await photonRequest(live, "/vcc/openApi/v4/pagingVccTradeOrder", {
        query: {
          pageIndex,
          pageSize: PAGE_SIZE,
          cardFormFactor: "virtual_card",
          createdAtStart: providerTime(from),
          createdAtEnd: providerTime(to),
        },
      });
      const rows = rowsOf(json);
      counts.fetched += rows.length;

      for (const row of rows) {
        const cardId = String(row.cardId || "");
        if (!cards.has(cardId)) {
          const page = cardId
            ? await context.entities.Card.filter({ photon_card_id: cardId }, { limit: 1 })
            : [];
          cards.set(cardId, (Array.isArray(page) ? page : page.items || [])[0] || null);
        }
        const card = cards.get(cardId);
        if (!card) { counts.unknown_card++; continue; }
        counts[await saveTransaction(context, card, row)]++;
      }

      const total = Number(json.total ?? json.data?.total);
      more = Number.isFinite(total) ? pageIndex * PAGE_SIZE < total : rows.length === PAGE_SIZE;
      pageIndex++;
    }

    // Bring every linked card's balance and status in line with PhotonPay.
    const balances = { checked: 0, updated: 0 };
    try {
      const localPage = await context.entities.Card.list({ limit: 500 });
      const local = new Map((Array.isArray(localPage) ? localPage : localPage.items || [])
        .filter((card) => card.photon_card_id).map((card) => [card.photon_card_id, card]));
      for (let cardPage = 1; local.size && cardPage <= 20; cardPage++) {
        const json = await photonRequest(live, "/vcc/openApi/v4/pagingVccCard", { query: { cardFormFactor: "virtual_card", pageIndex: cardPage, pageSize: 100 } });
        const rows = rowsOf(json);
        for (const row of rows) {
          const record = local.get(String(row.cardId || ""));
          if (!record) continue;
          balances.checked++;
          const updated = await refreshCardRecord(context, record, row);
          if (updated.balance !== record.balance || updated.status !== record.status) balances.updated++;
        }
        const total = Number(json.total ?? json.data?.total);
        if (Number.isFinite(total) ? cardPage * 100 >= total : rows.length < 100) break;
      }
    } catch (error) {
      console.log("Card balance refresh skipped:", error.message);
    }

    const logs_deleted = await cleanupLogs(context);
    const summary = {
      window: { from: providerTime(from), to: providerTime(to) },
      pages: pageIndex - 1,
      truncated: more,
      ...counts,
      applications,
      balances,
      logs_deleted,
    };
    await writeLog(live, {
      kind: "sync",
      method: "GET",
      path: "/vcc/openApi/v4/pagingVccTradeOrder",
      started_at: startedAt.toISOString(),
      finished_at: new Date().toISOString(),
      duration_ms: Date.now() - startedAt.getTime(),
      response_body: JSON.stringify(summary),
    });
    return Response.json(summary);
  } catch (error) {
    console.log("photonpayTransactionSync error:", error.message);
    return Response.json({ error: error.message || "Transaction sync failed" }, { status: 500 });
  }
}

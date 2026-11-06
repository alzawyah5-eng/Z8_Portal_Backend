// @ts-nocheck
const secrets = { get: (name) => process.env[name] || '' };
import { getConfig, getRelayConfig, photonRequest, resolveConfig, pickCard, resolveIssuedCard, photonUpload, maskIdNumber, refreshCardRecord, saveTransaction, unlockIfFunded, notifyClient, notifyHolderChange } from "./photonpay";

// PhotonPay's openCardHalo issues USD cards only.
const CURRENCIES = ["USD"];

// openCardHalo needs the issuing device's public IP and country for risk checks.
// The Nest controller supplies x-z8-client-ip from Express req.ip after
// stripping user-supplied forwarding headers. Forwarded IPs are trusted only
// when TRUSTED_PROXY_CIDRS explicitly identifies the immediate proxy.
function isPublicIp(value) {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) {
    const [a, b] = value.split(".").map(Number);
    if ([a, b].some((octet) => octet > 255)) return false;
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 192 && b === 0 && Number(value.split(".")[2]) === 0) return false;
    if (a === 192 && b === 0 && Number(value.split(".")[2]) === 2) return false;
    if (a === 192 && b === 88 && Number(value.split(".")[2]) === 99) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 198 && (b === 18 || b === 19)) return false;
    if (a === 198 && b === 51 && Number(value.split(".")[2]) === 100) return false;
    if (a === 203 && b === 0 && Number(value.split(".")[2]) === 113) return false;
    return true;
  }
  const ipv6 = value.toLowerCase().split("%")[0];
  if (!ipv6.includes(":") || !/^[0-9a-f:]+$/.test(ipv6)) return false;
  if (ipv6.startsWith("::ffff:")) {
    const mapped = ipv6.slice(7);
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(mapped)) return isPublicIp(mapped);
    const groups = mapped.split(":");
    if (groups.length === 2 && groups.every((group) => /^[0-9a-f]{1,4}$/.test(group))) {
      const high = parseInt(groups[0], 16);
      const low = parseInt(groups[1], 16);
      return isPublicIp(`${high >>> 8}.${high & 255}.${low >>> 8}.${low & 255}`);
    }
    return false;
  }
  const firstGroup = parseInt(ipv6.split(":")[0] || "0", 16);
  return firstGroup >= 0x2000 && firstGroup <= 0x3fff && !ipv6.startsWith("2001:db8:");
}

// Administrator-only actions: the administrator is a trusted, accountable
// actor and their own device address is the useful risk input, so the forwarded
// client address may be used there. No "user" role action reaches this.
function adminDeviceIp(req) {
  const value = String(req.headers.get("x-z8-client-ip") || "").trim();
  return value && isPublicIp(value) ? value : "";
}

function clientCountry(_req, picked) {
  const value = String(picked || "").trim().toUpperCase();
  return /^[A-Z]{2}$/.test(value) ? value : "";
}

function clean(value, max = 100) {
  return String(value === undefined || value === null ? "" : value).trim().slice(0, max);
}

function numberOrUndefined(value) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? n : undefined;
}

const RATE_LIMIT = 30;
const RATE_WINDOW_MS = 60_000;
const rateHits = new Map();

// One client card request at a time per cardholder. The allowance is counted
// from cards already stored, so two requests that read it before either card is
// written would both pass it and each apply for a real card at PhotonPay.
const cardRequestsInFlight = new Set();

function overRateLimit(accountId) {
  const now = Date.now();
  const recent = (rateHits.get(accountId) || []).filter((stamp) => now - stamp < RATE_WINDOW_MS);
  recent.push(now);
  rateHits.set(accountId, recent);
  if (rateHits.size > 500) {
    for (const [key, stamps] of rateHits) {
      if (!stamps.some((stamp) => now - stamp < RATE_WINDOW_MS)) rateHits.delete(key);
    }
  }
  return recent.length > RATE_LIMIT;
}

function requestId(prefix) {
  return `${prefix}${Date.now()}${Math.floor(Math.random() * 900 + 100)}`.slice(0, 64);
}


function rowsOf(json) {
  const data = json?.data;
  return Array.isArray(data) ? data : data?.list || data?.rows || [];
}

// PhotonPay addCardholder rules, shared by the administrator's direct
// registration and by client applications.
function validateHolder(input) {
  const problems = [];
  const text = (key, max, label) => {
    const value = clean(input[key], max + 1);
    if (!value) problems.push(`${label} is required`);
    else if (value.length > max) problems.push(`${label} must be ${max} characters or fewer`);
    return value;
  };
  const code2 = (key, label) => {
    const value = clean(input[key], 3).toUpperCase();
    if (!/^[A-Z]{2}$/.test(value)) problems.push(`${label} must be a two-letter country code`);
    return value;
  };
  const firstName = text("firstName", 40, "First name");
  const lastName = text("lastName", 40, "Last name");
  for (const [label, value] of [["First name", firstName], ["Last name", lastName]]) {
    if (value && !/^[\p{L} ]+$/u.test(value)) problems.push(`${label} may contain letters and spaces only`);
  }
  const dateOfBirth = clean(input.dateOfBirth, 10);
  const dob = new Date(`${dateOfBirth}T00:00:00Z`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateOfBirth) || Number.isNaN(dob.getTime()) || dob >= new Date()) {
    problems.push("Date of birth must be a past date (YYYY-MM-DD)");
  }
  const nationalityCountryCode = code2("nationalityCountryCode", "Nationality");
  const email = clean(input.email, 41).toLowerCase();
  if (email && (email.length > 40 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) problems.push("Email must be a valid address of 40 characters or fewer");
  const mobile = clean(input.mobile, 12).replace(/\D/g, "");
  const mobilePrefix = clean(input.mobilePrefix, 6).replace(/[^\d+]/g, "");
  if (!email && !mobile) problems.push("Enter an email or a mobile number");
  if (mobile && mobile.length > 11) problems.push("Mobile number may have at most 11 digits");
  if (mobile && !/^\+\d{1,4}$/.test(mobilePrefix)) problems.push("Mobile prefix must be + and 1 to 4 digits, e.g. +971");
  const residentialAddress = text("residentialAddress", 100, "Billing address");
  const residentialCity = text("residentialCity", 50, "City");
  const residentialState = text("residentialState", 50, "State or province");
  const residentialPostalCode = text("residentialPostalCode", 10, "Postal code");
  const residentialCountryCode = code2("residentialCountryCode", "Billing country");
  const certType = clean(input.certType, 20);
  if (!["id_card", "passport", "resident_permit"].includes(certType)) problems.push("Choose the ID type");
  const certId = text("certId", 64, "ID number");
  const certCountryCode = code2("certCountryCode", "ID issuing country");
  return {
    problems,
    fields: {
      firstName, lastName, dateOfBirth, nationalityCountryCode, email, mobile, mobilePrefix,
      residentialAddress, residentialCity, residentialState, residentialPostalCode, residentialCountryCode,
      certType, certId, certCountryCode,
    },
  };
}

function applicationFields(app) {
  return {
    firstName: app.first_name || "", lastName: app.last_name || "", dateOfBirth: app.date_of_birth || "",
    nationalityCountryCode: app.nationality || "", email: app.email || "", mobile: app.mobile || "",
    mobilePrefix: app.mobile_prefix || "", residentialAddress: app.address_line || "", residentialCity: app.city || "",
    residentialState: app.state || "", residentialPostalCode: app.postal_code || "", residentialCountryCode: app.country || "",
    certType: app.cert_type || "", certId: app.cert_id || "", certCountryCode: app.cert_country || "",
  };
}

function fieldsAsInput(fields) {
  return { ...fields };
}

async function registerWithPhotonPay(context, live, f, portrait, reverseSide, extra = {}) {
  const body = {
    firstName: f.firstName, lastName: f.lastName, dateOfBirth: f.dateOfBirth, nationalityCountryCode: f.nationalityCountryCode,
    ...(f.email ? { email: f.email } : {}),
    ...(f.mobile ? { mobile: f.mobile, mobilePrefix: f.mobilePrefix } : {}),
    residentialAddress: f.residentialAddress, residentialCity: f.residentialCity, residentialState: f.residentialState,
    residentialPostalCode: f.residentialPostalCode, residentialCountryCode: f.residentialCountryCode,
    certType: f.certType, certId: f.certId, certCountryCode: f.certCountryCode, portrait,
    ...(f.certType !== "passport" && reverseSide ? { reverseSide } : {}),
  };
  const json = await photonRequest(live, "/vcc/openApi/v4/addCardholder", { method: "POST", body });
  const data = json.data || {};
  if (!data.cardholderId) throw Object.assign(new Error("PhotonPay did not return a cardholder ID."), { stage: "provider" });
  const saved = await context.entities.Cardholder.create({
    full_name: `${f.firstName} ${f.lastName}`.trim(),
    first_name: f.firstName, last_name: f.lastName, email: f.email,
    phone: f.mobile ? `${f.mobilePrefix} ${f.mobile}` : "",
    date_of_birth: f.dateOfBirth, nationality: f.nationalityCountryCode,
    address_line: f.residentialAddress, city: f.residentialCity, state: f.residentialState,
    postal_code: f.residentialPostalCode, country: f.residentialCountryCode,
    cert_type: f.certType,
    // Only the last four characters of the ID number are kept in Z8.
    cert_id: maskIdNumber(f.certId),
    cert_country: f.certCountryCode,
    photon_cardholder_id: clean(data.cardholderId, 64),
    master_account_email: live.masterAccountEmail || "",
    ...holderState(data),
    // Who receives the automatically issued card, and the device to report to
    // PhotonPay when it is issued (openCardHalo ipAddress / gpsCountry).
    owner_email: String(extra.ownerEmail || f.email || "").toLowerCase(),
    device_ip: extra.deviceIp || "",
    device_country: extra.deviceCountry || "",
  });
  return { saved, data };
}

// ---------------------------------------------------------------------------
// Card on request: once a client is approved by an administrator and by
// PhotonPay, they can ask for a Regular card themselves. It is applied for at
// PhotonPay straight away; its details stay locked for the client until an
// administrator funds it (top_up).
// ---------------------------------------------------------------------------

const SETTINGS_DEFAULTS = { client_requests_enabled: true, max_cards_per_client: 1, default_max_on_daily: null, default_max_on_monthly: null, default_max_on_percent: null, min_opening_amount: 20,
  tier_start_amount: 250, tier_plum_from: 10000, tier_crimson_from: 50000,
  tier_emerald_enabled: true, tier_plum_enabled: true, tier_crimson_enabled: true };

async function programmeSettings(context) {
  const page = await context.entities.ProgrammeSettings.list({ limit: 1 }).catch(() => []);
  const row = (Array.isArray(page) ? page : page.items || [])[0];
  return { ...SETTINGS_DEFAULTS, ...(row || {}) };
}

// A client's cards that are still open. Only the ones they requested
// themselves count against their allowance; cards an administrator issued do not.
async function clientCards(context, holder) {
  const page = await context.entities.Card.filter({ cardholder_id: holder.id }, { limit: 50 });
  return (Array.isArray(page) ? page : page.items || []).filter((card) => !["cancelled", "failed"].includes(card.status));
}

// The client's verification as PhotonPay sees it, once their details were
// sent there: verified (approved), still being checked, or held up.
function identityState(holder) {
  if (!holder) return null;
  const review = String(holder.review_status || "").toLowerCase();
  const status = holder.status === "active" ? "verified"
    : holder.status === "suspended" ? "declined"
    : ["modify", "cert_required"].includes(review) ? "needs_changes"
    : "checking";
  return { status, full_name: holder.full_name || `${holder.first_name || ""} ${holder.last_name || ""}`.trim() };
}

// What a client says a card is for. The label also names the card, so a
// client with several cards can tell them apart.
const CARD_PURPOSES = {
  online_shopping: "Online shopping",
  advertising: "Advertising",
  subscriptions: "Subscriptions",
  travel: "Travel",
  business_expenses: "Business expenses",
  other: "Other",
};

function cardPurpose(input) {
  const purpose = Object.hasOwn(CARD_PURPOSES, input?.purpose) ? input.purpose : "";
  const detail = clean(input?.purposeDetail, 60);
  if (!purpose) return { error: "Choose what you'll use the card for." };
  if (purpose === "other" && detail.length < 3) return { error: "Tell us what you'll use the card for (at least 3 characters)." };
  return { purpose, detail: purpose === "other" ? detail : "", label: purpose === "other" ? detail : CARD_PURPOSES[purpose] };
}

// The smallest opening balance a Regular card can be created with: PhotonPay
// refuses less ("The arrival amount to be paid must be greater than 20USD").
function minOpeningAmount(settings) {
  return Math.max(20, Math.round((Number(settings.min_opening_amount) || 20) * 100) / 100);
}

async function pendingCardRequests(context, holder) {
  const page = await context.entities.CardRequest.filter({ cardholder_record_id: holder.id, status: "pending" }, { sort: "created_date", limit: 20 });
  return Array.isArray(page) ? page : page.items || [];
}

// The client's most recent card request, for the status they see.
async function latestCardRequest(context, holder) {
  const page = await context.entities.CardRequest.filter({ cardholder_record_id: holder.id }, { sort: "-created_date", limit: 1 });
  return (Array.isArray(page) ? page : page.items || [])[0] || null;
}

// A card request as the client may see it.
function publicCardRequest(row) {
  return row && {
    id: row.id, status: row.status, amount: row.amount, approved_amount: row.approved_amount ?? null,
    purpose: row.purpose || "", purpose_detail: row.purpose_detail || "", tier: row.tier || "",
    requested_at: row.requested_at || row.created_date || "", reviewed_at: row.reviewed_at || "",
    review_note: row.status === "rejected" ? row.review_note || "" : "",
  };
}

// ---------------------------------------------------------------------------
// Client accounts: money a client has deposited with Z8. The balance is the
// sum of completed AccountEntry rows; card requests waiting for approval hold
// part of it, and only the rest is available for new cards.
// ---------------------------------------------------------------------------

const round2 = (value) => Math.round((Number(value) || 0) * 100) / 100;
const rowsFrom = (page) => (Array.isArray(page) ? page : page?.items || []);
const DEPOSIT_METHODS = ["bank_transfer", "cash", "other"];
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ---- Card tiers ---------------------------------------------------------------
// Tells a client when a deposit lifts them into a tier (first card or upgrade).
async function announceTier(context, email, before, after) {
  const settings = await programmeSettings(context);
  const was = tierStanding(before, settings).tier;
  const now = tierStanding(after, settings).tier;
  if (!now || now === was) return;
  await notifyClient(context, email, {
    kind: "card", tone: "success",
    title: was ? `You've reached ${TIER_NAMES[now]}` : `You can now request your ${TIER_NAMES[now]} card`,
    body: was ? `Your deposits unlock the ${TIER_NAMES[now]} card. Request it from your Cards page.` : "Your deposits unlock your first card. Request it from your Cards page.",
    link: "/cards", key: `tier:${now}`,
  });
}
// A client's tier follows the total they have deposited with Z8 (confirmed
// deposits only, so it never drops when they spend): Emerald from the starting
// amount, then Plum, then Crimson. They may request a card of their tier or
// any tier below it.
const TIER_ORDER = ["emerald", "plum", "crimson"];
const TIER_NAMES = { emerald: "Emerald", plum: "Plum", crimson: "Crimson" };

function tierLadder(settings) {
  const start = Math.max(1, round2(settings.tier_start_amount) || 250);
  const plum = Math.max(start + 1, round2(settings.tier_plum_from) || 10000);
  const crimson = Math.max(plum + 1, round2(settings.tier_crimson_from) || 50000);
  return [{ id: "emerald", from: start }, { id: "plum", from: plum }, { id: "crimson", from: crimson }];
}

// Tiers the administrator offers in the app. A switched-off tier is not shown,
// requested or counted as a level: a client who qualifies for it gets the
// highest offered tier at or below it.
const tierOffered = (settings, id) => settings[`tier_${id}_enabled`] !== false;

function tierStanding(deposited, settings) {
  const ladder = tierLadder(settings).filter((step) => tierOffered(settings, step.id));
  const reached = ladder.filter((step) => deposited >= step.from);
  const tier = reached.length ? reached[reached.length - 1].id : "";
  const next = ladder.find((step) => deposited < step.from) || null;
  return {
    tier, tier_name: tier ? TIER_NAMES[tier] : "", deposited: round2(deposited),
    eligible_tiers: reached.map((step) => step.id),
    next_tier: next ? { id: next.id, name: TIER_NAMES[next.id], from: next.from, remaining: round2(next.from - deposited) } : null,
    ladder: ladder.map((step) => ({ ...step, name: TIER_NAMES[step.id] })),
  };
}

async function walletOf(context, email) {
  const owner = String(email || "").toLowerCase();
  if (!owner) return { balance: 0, held: 0, available: 0, deposited: 0, entries: [], holds: [] };
  const db = context.entities;
  const entries = rowsFrom(await db.AccountEntry.filter({ owner_email: owner }, { sort: "-created_date", limit: 500 }));
  const holds = rowsFrom(await db.CardRequest.filter({ owner_email: owner, status: "pending" }, { limit: 20 }));
  const balance = round2(entries.filter((entry) => entry.status === "completed").reduce((sum, entry) => sum + (Number(entry.amount) || 0), 0));
  const held = round2(holds.reduce((sum, row) => sum + (Number(row.amount) || 0), 0));
  // Money the client has paid in (confirmed deposits): this sets their tier.
  const deposited = round2(entries.filter((entry) => entry.kind === "deposit" && entry.status === "completed").reduce((sum, entry) => sum + Math.max(0, Number(entry.amount) || 0), 0));
  return { balance, held, available: round2(balance - held), deposited, entries, holds };
}

// An account movement as the client may see it (no internal notes).
function publicEntry(entry) {
  return {
    id: entry.id, kind: entry.kind, status: entry.status, amount: entry.amount, currency: entry.currency || "USD",
    method: entry.method || "", reference: entry.reference || "", note: entry.note || "",
    date: entry.recorded_at || entry.created_date || "",
    has_proof: Boolean(entry.proof_file_uri), proof_name: entry.proof_file_uri ? entry.proof_name || "" : "", proof_type: entry.proof_file_uri ? entry.proof_type || "" : "",
  };
}

// A card's money is the client's unless the card belongs to an administrator.
async function isClientMoney(context, email) {
  const owner = String(email || "").toLowerCase();
  if (!owner) return false;
  const users = rowsFrom(await context.entities.User.filter({ email: owner }, { limit: 5 }).catch(() => []));
  return !users.some((row) => row.role === "admin");
}

async function addEntry(context, data) {
  return context.entities.AccountEntry.create({ currency: "USD", recorded_at: new Date().toISOString(), ...data });
}

// What a verified client may do about getting a card, for the Cards page.
async function cardRequestState(context, holder) {
  const settings = await programmeSettings(context);
  const base = await cardRequestBase(context, holder, settings);
  return { ...base, min_amount: minOpeningAmount(settings) };
}

async function cardRequestBase(context, holder, settings) {
  if (!holder) return { verified: false, can_request: false, reason: "Verify your identity to request a card." };
  if (holder.status !== "active") return { verified: false, can_request: false, reason: "Your identity check is still in progress." };
  if (settings.client_requests_enabled === false) return { verified: true, can_request: false, reason: "Card requests are paused. Please contact support." };
  const waiting = await pendingCardRequests(context, holder);
  if (waiting.length) return { verified: true, can_request: false, waiting_approval: true, reason: `Your card request for ${Number(waiting[0].amount).toFixed(2)} USD is waiting for approval.` };
  const cards = await clientCards(context, holder);
  if (cards.some((card) => card.status === "pending")) return { verified: true, can_request: false, reason: "Your card is being created. It appears here as soon as PhotonPay confirms it." };
  const max = Math.max(1, Math.floor(Number(settings.max_cards_per_client) || 1));
  const requested = cards.filter((card) => card.auto_issued);
  if (requested.length >= max) return { verified: true, can_request: false, reason: max === 1 ? "You already requested your card." : `You already requested ${requested.length} cards, the most allowed.` };
  // A card is created with money from the client's own account, so they need
  // at least the minimum opening amount available first.
  const wallet = await walletOf(context, holder.owner_email);
  const min = minOpeningAmount(settings);
  const standing = tierStanding(wallet.deposited, settings);
  const money = { balance: wallet.balance, available: wallet.available, ...standing };
  if (!standing.ladder.length) return { verified: true, can_request: false, reason: "Card requests are paused. Please contact support.", ...money };
  if (!standing.tier) {
    const first = standing.ladder[0];
    return {
      verified: true, can_request: false, needs_funds: true, ...money,
      reason: `Fund your account first. Your first card (${first.name}) needs ${first.from.toFixed(2)} USD deposited in total; you've deposited ${wallet.deposited.toFixed(2)} USD.`,
    };
  }
  if (wallet.available < min) {
    return {
      verified: true, can_request: false, needs_funds: true, ...money,
      reason: `Fund your account first. A card needs at least ${min.toFixed(2)} USD, and your available balance is ${wallet.available.toFixed(2)} USD.`,
    };
  }
  return { verified: true, can_request: true, reason: "", ...money };
}

// A request reserves its slot in the database before anything reaches
// PhotonPay. The allowance is counted from stored cards, so the reservation is
// what holds the limit when requests arrive in parallel on several instances:
// old reservations keep their slot, and a request that reserved behind the
// allowance stands down instead of applying for another card.
async function holdsCardSlot(context, holder, reservationId, max) {
  const mine = (await clientCards(context, holder)).filter((card) => card.auto_issued);
  const key = (card) => `${card.created_date || ""}|${card.id}`;
  mine.sort((a, b) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0));
  const index = mine.findIndex((card) => card.id === reservationId);
  return index !== -1 && index < max;
}

// A reservation left behind by a request that never reached PhotonPay (a crash
// or a timeout) would block the client for good, so stale ones are dropped first.
async function clearStaleReservations(context, holder) {
  const stale = (await clientCards(context, holder)).filter((card) => card.auto_issued && card.status === "pending" && !card.request_id
    && Date.now() - (Date.parse(card.created_date || "") || 0) > 10 * 60_000);
  for (const card of stale) await context.entities.Card.delete(card.id).catch(() => null);
}

// Creates a client's Regular card once an administrator approved their request,
// loaded with the amount the client deposited. The approving administrator's
// device is the one reported to PhotonPay (ipAddress / gpsCountry).
async function issueRegularCard(context, live, holder, { gpsCountry, ipAddress, amount, purpose = "", purposeDetail = "", tier = "" }) {
  const note = async (status, text) => {
    await context.entities.Cardholder.update(holder.id, { auto_issue_status: status, auto_issue_note: String(text).slice(0, 500) });
    return { status, note: text };
  };
  const settings = await programmeSettings(context);
  const ownerEmail = String(holder.owner_email || holder.email || "").toLowerCase();
  // The device reported is the approving administrator's (adminDeviceIp), never
  // a client-supplied address and never previous platform's hosting hop (VCC3040).
  const funding = (await photonRequest(live, "/wallet/openApi/v4/account/single", { query: { currency: "USD", accountType: "FT10001" } })).data || {};
  const accountId = clean(funding.accountNo, 64);
  if (!accountId) return note("failed", "No USD PhotonPay account to fund Regular cards from.");
  const available = Number(funding.realTimeBalance);
  if (Number.isFinite(available) && available < amount) {
    return note("failed", `Your USD account holds ${available.toFixed(2)} USD, less than the ${amount.toFixed(2)} USD to load. Add funds at PhotonPay first.`);
  }
  const base = {
    ipAddress, gpsCountry, cardholderId: holder.photon_cardholder_id,
    cardCurrency: "USD", cardType: "recharge", cardFormFactor: "virtual_card", accountId,
    // Named after its purpose ("Ana · Advertising") so cards are easy to tell apart.
    nickname: clean(`${holder.first_name || holder.full_name || "Client"} · ${purpose ? (purpose === "other" ? purposeDetail || "Card" : CARD_PURPOSES[purpose] || "Card") : "card"}`, 50),
    maxOnDaily: numberOrUndefined(settings.default_max_on_daily),
    maxOnMonthly: numberOrUndefined(settings.default_max_on_monthly),
    maxOnPercent: numberOrUndefined(settings.default_max_on_percent),
    transactionLimitType: "unlimited",
  };
  // Reserve the slot before the provider call; the row is the card itself once
  // PhotonPay accepts, and it is removed again if the request does not go through.
  const reservation = await context.entities.Card.create({
    nickname: base.nickname, owner_email: ownerEmail, currency: "USD", card_type: "recharge", form_factor: "virtual_card",
    status: "pending", balance: 0, max_on_daily: base.maxOnDaily, max_on_monthly: base.maxOnMonthly, max_on_percent: base.maxOnPercent,
    transaction_limit_type: "unlimited", cardholder_name: holder.full_name, cardholder_id: holder.id,
    photon_cardholder_id: holder.photon_cardholder_id, auto_issued: true,
    ...(purpose ? { purpose, purpose_detail: purposeDetail } : {}),
    ...(TIER_ORDER.includes(tier) ? { tier } : {}),
  });
  const max = Math.max(1, Math.floor(Number(settings.max_cards_per_client) || 1));
  if (!(await holdsCardSlot(context, holder, reservation.id, max))) {
    await context.entities.Card.delete(reservation.id).catch(() => null);
    return note("failed", "This client already holds the most requested cards allowed (Connection & API → Cards per client).");
  }
  // Nothing of this request may be left behind when it stops here.
  const fail = async (text) => {
    await context.entities.Card.delete(reservation.id).catch(() => null);
    return note("failed", text);
  };
  // PhotonPay requires the opening balance on a Regular card (VCC1039 without
  // one, VCC1081 under 20 USD): it is the client's own deposit.
  const body = { requestId: requestId("Z8A"), ...base, rechargeAmount: amount };
  let json;
  try {
    json = await photonRequest(live, "/vcc/openApi/v4/openCardHalo", { method: "POST", body });
  } catch (error) {
    return fail(`PhotonPay refused the card: ${error.message}`);
  }
  const data = json.data || {};
  if (String(data.createCardStatus || "").toLowerCase() === "failed") return fail(`PhotonPay declined the card application (request ${body.requestId}).`);
  // The opening balance is the client's deposit, so the card is funded from
  // the start and its details are not locked.
  const card = await context.entities.Card.update(reservation.id, { request_id: body.requestId, funded_at: new Date().toISOString() });
  await context.entities.CardTransaction.create({
    kind: "event", event: "Card approved and funded", card_id: card.id, card_nickname: card.nickname, amount,
    currency: "USD", status: "pending", occurred_at: new Date().toISOString(), owner_email: ownerEmail,
    note: `Card request approved. Created with an opening balance of ${amount.toFixed(2)} USD from the client's deposit.`,
  });
  await note("requested", `Regular card created with ${amount.toFixed(2)} USD (${body.requestId}).`);
  return { status: "requested", card_record_id: card.id, request_id: body.requestId };
}

function registrationResult(saved, data) {
  return {
    cardholder_record_id: saved.id,
    photon_cardholder_id: data.cardholderId,
    status: saved.status,
    provider_status: saved.provider_status,
    review_status: saved.review_status,
    id_info_requirement: clean(data.idInfoRequirement, 2),
    reason: clean(data.reason, 600),
  };
}

function imageKind(bytes) {
  if (bytes[0] === 0xff && bytes[1] === 0xd8) return "image/jpeg";
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) return "image/png";
  return "";
}

// ---- ID photos for a client's own application -------------------------------
// A client posts the photo's bytes to this function, which stores them in the
// app's private files and returns an opaque token binding that stored file to
// the account. submit_registration accepts only such tokens, so a caller can
// never name a storage path of their choosing (for example another client's
// uploaded document) as their own identity photo.
const PRIVATE_APP_FILE = /^mp\/private\/[a-z0-9]{20,32}\/[A-Za-z0-9][A-Za-z0-9._-]{0,140}\.(?:jpe?g|png)$/i;

function isPrivateAppFile(uri) {
  return PRIVATE_APP_FILE.test(String(uri || ""));
}

function tokenKeySecret() {
  try {
    return String(secrets.get("PHOTONPAY_APP_SECRET") || secrets.get("PHOTONPAY_RELAY_SECRET") || "").trim();
  } catch {
    return "";
  }
}

function base64Url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function textToBase64Url(text) {
  return base64Url(new TextEncoder().encode(text));
}

function base64UrlToText(value) {
  try {
    const binary = atob(String(value).replace(/-/g, "+").replace(/_/g, "/"));
    return new TextDecoder().decode(Uint8Array.from(binary, (c) => c.charCodeAt(0)));
  } catch {
    return "";
  }
}

async function photoTokenKey() {
  const secret = tokenKeySecret();
  if (!secret) return null;
  return crypto.subtle.importKey("raw", new TextEncoder().encode(`z8-id-photo:${secret}`), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

function sameText(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function signPhotoToken(email, uri) {
  const key = await photoTokenKey();
  if (!key) return "";
  const payload = `${email}|${uri}`;
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return `${textToBase64Url(payload)}.${base64Url(signature)}`;
}

// The stored file for a token this function issued to this account, or "" when
// the token is missing, altered, foreign, or no longer verifiable.
async function readPhotoToken(token, email) {
  const [encoded, signature] = String(token || "").split(".");
  if (!encoded || !signature) return "";
  const payload = base64UrlToText(encoded);
  const key = await photoTokenKey();
  if (!payload || !key) return "";
  const expected = base64Url(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload)));
  if (!sameText(expected, signature)) return "";
  const split = payload.indexOf("|");
  if (split < 0 || payload.slice(0, split) !== email) return "";
  const uri = payload.slice(split + 1);
  return isPrivateAppFile(uri) ? uri : "";
}

// ---- Proof of payment for a deposit -----------------------------------------
// A photo or PDF of a transfer receipt or cash slip, stored in private files
// and handed back as a token bound to the uploader (domain-separated from ID
// photo tokens). Only administrators and the uploading client can open it,
// through a short-lived signed link.
const PROOF_FILE = /^mp\/private\/[a-z0-9]{20,32}\/[A-Za-z0-9][A-Za-z0-9._-]{0,140}\.(?:jpe?g|png|pdf)$/i;
const MAX_PROOF_BYTES = 6 * 1024 * 1024;

function proofKind(bytes) {
  const image = imageKind(bytes);
  if (image) return image;
  if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) return "application/pdf";
  return "";
}

const proofSubject = (email) => `deposit-proof:${email}`;

async function readProofToken(token, email) {
  const [encoded, signature] = String(token || "").split(".");
  if (!encoded || !signature) return "";
  const payload = base64UrlToText(encoded);
  const key = await photoTokenKey();
  if (!payload || !key) return "";
  const expected = base64Url(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload)));
  if (!sameText(expected, signature)) return "";
  const split = payload.lastIndexOf("|");
  if (split < 0 || payload.slice(0, split) !== proofSubject(email)) return "";
  const uri = payload.slice(split + 1);
  return PROOF_FILE.test(uri) ? uri : "";
}

// Fields to store on an AccountEntry for a verified proof token ({} without one).
async function proofFields(token, email, name) {
  if (!token) return {};
  const uri = await readProofToken(token, email);
  if (!uri) return null;
  return { proof_file_uri: uri, proof_type: /\.pdf$/i.test(uri) ? "application/pdf" : "image", proof_name: clean(name, 120) };
}

// Reads an ID photo from private previous platform storage and uploads it to PhotonPay,
// returning PhotonPay's file key.
async function forwardPrivatePhoto(context, live, fileUri, side) {
  if (!fileUri) throw new Error(`The ${side} ID photo is missing from the application.`);
  if (!isPrivateAppFile(fileUri)) throw new Error(`The ${side} ID photo is not stored in this app's private storage.`);
  const { signed_url: url } = await context.files.createSignedUrl({ file_uri: fileUri, expires_in: 120 });
  const res = await fetch(url, { signal: AbortSignal.timeout(30000) });
  if (!res.ok) throw new Error(`The ${side} ID photo could not be read from storage (HTTP ${res.status}).`);
  const bytes = new Uint8Array(await res.arrayBuffer());
  const kind = imageKind(bytes);
  if (!kind) throw new Error(`The ${side} ID photo is not a JPG or PNG image.`);
  if (bytes.length > 6 * 1024 * 1024) throw new Error(`The ${side} ID photo is larger than PhotonPay's 6 MB limit.`);
  return photonUpload(live, "issuing_cardholder_identity_certificate", bytes, `id-${side}.${kind === "image/png" ? "png" : "jpg"}`, kind);
}

function holderState(source) {
  const providerStatus = clean(source.status, 30).toLowerCase() || "unknown";
  const reviewStatus = clean(source.cardholderReviewStatus, 30).toLowerCase().split(":")[0] || "unknown";
  // PhotonPay: with idInfoRequirement N no identity review applies and a card
  // can be issued once the cardholder is normal; with Y the review must also
  // be approved.
  const noReviewNeeded = clean(source.idInfoRequirement, 2).toUpperCase() === "N" && !["rejected", "modify"].includes(reviewStatus);
  const approved = providerStatus === "normal" && (reviewStatus === "approved" || noReviewNeeded);
  return {
    provider_status: providerStatus,
    review_status: reviewStatus,
    status: approved ? "active" : ["disabled", "rejected"].includes(providerStatus) || reviewStatus === "rejected" ? "suspended" : "pending",
    review_reason: clean(source.reason, 600),
    synced_at: new Date().toISOString(),
  };
}

async function saveHolder(context, source, cfg, existing = null) {
  const providerId = clean(source.cardholderId, 64);
  if (!providerId || source.matrixAccount) return null;
  if (!existing) {
    const page = await context.entities.Cardholder.filter(
      { photon_cardholder_id: providerId }, { limit: 1 },
    );
    existing = (Array.isArray(page) ? page : page.items || [])[0] || null;
  }
  // Mirror PhotonPay's card user record (pagingVccCardholder) field for field,
  // so this list matches the portal's Issuing → Card User. Only fields
  // PhotonPay actually returned are written; Z8's own fields (owner_email,
  // device, automatic card) are never touched here.
  const prefix = clean(source.mobilePrefix, 8).replace(/[^\d]/g, "");
  const mobile = clean(source.mobile, 20);
  const given = {
    first_name: clean(source.firstName, 40),
    last_name: clean(source.lastName, 40),
    email: clean(source.email, 254).toLowerCase(),
    phone: mobile ? `${prefix ? `+${prefix} ` : ""}${mobile}` : "",
    date_of_birth: clean(source.dateOfBirth, 10),
    nationality: clean(source.nationalityCountryCode, 2).toUpperCase(),
    address_line: clean(source.residentialAddress, 100),
    city: clean(source.residentialCity, 50),
    state: clean(source.residentialState, 50),
    postal_code: clean(source.residentialPostalCode, 10),
    country: clean(source.residentialCountryCode, 2).toUpperCase(),
    cert_type: ["id_card", "passport", "resident_permit"].includes(source.certType) ? source.certType : "",
    // PhotonPay already masks this; mask again in case it ever does not.
    cert_id: source.certId ? (String(source.certId).includes("*") ? clean(source.certId, 64) : maskIdNumber(source.certId)) : "",
    cert_country: clean(source.certCountryCode, 2).toUpperCase(),
    photon_created_at: clean(source.createdAt, 40),
    is_legal: clean(source.isLegal, 1).toUpperCase(),
    id_info_requirement: clean(source.idInfoRequirement, 1).toUpperCase(),
  };
  const data = {
    ...Object.fromEntries(Object.entries(given).filter(([, value]) => value)),
    full_name: [given.first_name, given.last_name].filter(Boolean).join(" ") || existing?.full_name || "Cardholder",
    photon_cardholder_id: providerId,
    master_account_email: cfg.masterAccountEmail || "",
    ...holderState(source),
  };
  if (!existing) return context.entities.Cardholder.create(data);
  const saved = await context.entities.Cardholder.update(existing.id, data);
  await notifyHolderChange(context, existing, { ...existing, ...data });
  return saved;
}

export default async function (req, context) {
  let admin = false;
  try {
    if (req.method !== "POST") return Response.json({ error: "Method not allowed" }, { status: 405, headers: { Allow: "POST" } });
    const user = await context.auth.me().catch((e) => (e.status === 401 ? null : Promise.reject(e)));
    if (!user) return Response.json({ error: "Unauthorized" }, { status: 401 });

    const payload = await req.json().catch(() => ({}));
    const action = clean(payload.action, 32);
    const input = payload.payload || {};
    admin = user.role === "admin";
    if (!admin && user.role !== "user") {
      return Response.json({ error: "Account access is unavailable" }, { status: 403 });
    }
    const adminActions = ["status", "bins", "balance", "list", "issue", "assign", "sync_holders", "add_holder", "upload_id_image",
      "update_card", "sandbox_txn", "edit_holder",
      "approve_application", "reject_application", "application_photo", "approve_card_request", "reject_card_request",
      "wallet_overview", "wallet_client", "wallet_record", "wallet_review", "deposit_proof"];
    // Top-ups are open to a card's owner too: a client adds credit from their own account balance.
    const cardActions = ["detail", "refresh", "freeze", "unfreeze", "cancel", "resolve", "unblock_cvv", "top_up_quote", "top_up_confirm"];
    // Administrator-only actions that act on one local card record.
    const adminCardActions = ["update_card", "sandbox_txn"];
    const selfActions = ["submit_registration", "my_registration", "request_card", "cancel_card_request", "store_id_photo", "my_wallet", "report_deposit",
      "store_deposit_proof", "my_deposit_proof"];
    if (!adminActions.includes(action) && !cardActions.includes(action) && !selfActions.includes(action)) {
      return Response.json({ error: "Unsupported action" }, { status: 400 });
    }
    if (adminActions.includes(action) && !admin) {
      return Response.json({ error: "Administrator access required" }, { status: 403 });
    }

    // ---- Client self-registration: stored in Z8, never sent to PhotonPay here.
    const myEmail = String(user.email || "").toLowerCase();
    const myApplications = async () => {
      const page = await context.entities.CardholderApplication.filter({ owner_email: myEmail }, { sort: "-created_date", limit: 20 });
      return Array.isArray(page) ? page : page.items || [];
    };
    const publicApplication = (app) => app && ({
      id: app.id, status: app.status, submitted_at: app.submitted_at, reviewed_at: app.reviewed_at || "",
      review_note: app.status === "rejected" ? app.review_note || "" : "",
      full_name: `${app.first_name || ""} ${app.last_name || ""}`.trim(),
    });

    // The client's own PhotonPay card user, if any. Records created before
    // owner links existed (or by an administrator) are found through the
    // client's approved application, a card issued to them, or the email
    // PhotonPay holds, and are linked to this login from then on. A record
    // already linked to another login is never taken over.
    const myHolder = async () => {
      const db = context.entities;
      const rowsOf = (page) => (Array.isArray(page) ? page : page?.items || []);
      const pick = (rows) => rows.find((row) => row.status === "active") || rows[0] || null;
      const owned = pick(rowsOf(await db.Cardholder.filter({ owner_email: myEmail }, { sort: "-created_date", limit: 10 })));
      if (owned) return owned;
      const unclaimed = (row) => row && !row.owner_email;
      const candidates = [];
      const ids = new Set();
      for (const app of await myApplications()) {
        if (app.status === "approved" && app.cardholder_record_id) ids.add(app.cardholder_record_id);
      }
      for (const card of rowsOf(await db.Card.filter({ owner_email: myEmail }, { limit: 20 }))) {
        if (card.cardholder_id) ids.add(card.cardholder_id);
      }
      for (const id of ids) {
        const row = await db.Cardholder.get(id).catch(() => null);
        if (unclaimed(row)) candidates.push(row);
      }
      if (!candidates.length) {
        candidates.push(...rowsOf(await db.Cardholder.filter({ email: myEmail }, { sort: "-created_date", limit: 10 })).filter(unclaimed));
      }
      const found = pick(candidates);
      if (found) {
        await db.Cardholder.update(found.id, { owner_email: myEmail }).catch(() => null);
        found.owner_email = myEmail;
      }
      return found;
    };

    if (action === "my_registration") {
      const [latest] = await myApplications();
      const holder = myEmail ? await myHolder() : null;
      return Response.json({
        application: publicApplication(latest) || null, account_email: myEmail,
        identity: identityState(holder), card_request: await cardRequestState(context, holder),
        latest_card_request: holder ? publicCardRequest(await latestCardRequest(context, holder)) : null,
      });
    }

    if (action === "request_card") {
      // A verified client asks for a Regular card with the amount they
      // deposited. Nothing reaches PhotonPay until an administrator approves it.
      if (overRateLimit(user.id)) return Response.json({ error: "Too many requests. Please wait a minute and try again." }, { status: 429 });
      const holder = myEmail ? await myHolder() : null;
      if (holder) await clearStaleReservations(context, holder);
      const state = await cardRequestState(context, holder);
      if (!state.can_request) return Response.json({ error: state.reason, card_request: state }, { status: state.verified ? 409 : 403 });
      const amount = Math.round(Number(input.amount) * 100) / 100;
      if (!Number.isFinite(amount) || amount < state.min_amount) {
        return Response.json({ error: `The minimum opening amount is ${state.min_amount.toFixed(2)} USD.`, card_request: state }, { status: 400 });
      }
      if (amount > 100000) return Response.json({ error: "Enter an amount up to 100,000 USD." }, { status: 400 });
      const use = cardPurpose(input);
      if (use.error) return Response.json({ error: use.error, card_request: state }, { status: 400 });
      // Their own tier unless they pick a lower one; never a tier above it.
      const tier = input.tier ? String(input.tier) : state.tier;
      if (!state.eligible_tiers.includes(tier)) {
        const step = state.ladder.find((item) => item.id === tier);
        const offered = TIER_ORDER.includes(tier) ? Boolean(step) : true;
        return Response.json({
          error: !offered ? `The ${TIER_NAMES[tier]} card isn't available right now.` : step ? `The ${step.name} card needs ${step.from.toFixed(2)} USD deposited in total; you've deposited ${state.deposited.toFixed(2)} USD.` : "Choose a card.",
          card_request: state,
        }, { status: 403 });
      }
      if (amount > round2(state.available)) {
        return Response.json({
          error: `Not enough balance. Your available balance is ${round2(state.available).toFixed(2)} USD. Fund your account or request a smaller amount.`,
          needs_funds: true, card_request: state,
        }, { status: 402 });
      }
      const created = await context.entities.CardRequest.create({
        status: "pending", owner_email: myEmail, cardholder_record_id: holder.id,
        photon_cardholder_id: holder.photon_cardholder_id, client_name: holder.full_name || "",
        amount, currency: "USD", requested_at: new Date().toISOString(),
        client_note: clean(input.note, 300),
        purpose: use.purpose, purpose_detail: use.detail, tier,
      });
      // Two taps at once: the earliest pending request stands, later ones go.
      const pending = await pendingCardRequests(context, holder);
      if (pending.length > 1 && pending[0].id !== created.id) {
        await context.entities.CardRequest.delete(created.id).catch(() => null);
        return Response.json({ error: "Your card request is already waiting for approval." }, { status: 409 });
      }
      return Response.json({ request: publicCardRequest(created), card_request: await cardRequestState(context, holder) });
    }

    if (action === "cancel_card_request") {
      const holder = myEmail ? await myHolder() : null;
      const row = await context.entities.CardRequest.get(clean(input.requestId, 64)).catch(() => null);
      if (!holder || !row || row.cardholder_record_id !== holder.id || row.owner_email !== myEmail) {
        return Response.json({ error: "Card request not found." }, { status: 404 });
      }
      if (row.status !== "pending") return Response.json({ error: `This request is already ${row.status}.` }, { status: 409 });
      await context.entities.CardRequest.update(row.id, { status: "cancelled", reviewed_at: new Date().toISOString() });
      return Response.json({ ok: true, card_request: await cardRequestState(context, holder) });
    }

    // ---- Client accounts -----------------------------------------------------
    if (action === "my_wallet") {
      const wallet = await walletOf(context, myEmail);
      const settings = await programmeSettings(context);
      return Response.json({
        balance: wallet.balance, held: wallet.held, available: wallet.available, currency: "USD",
        min_amount: minOpeningAmount(settings), funding_instructions: String(settings.funding_instructions || "").slice(0, 3000),
        ...tierStanding(wallet.deposited, settings),
        entries: wallet.entries.slice(0, 50).map(publicEntry),
      });
    }

    if (action === "report_deposit") {
      // The client tells us they sent money; it counts once an administrator confirms it.
      if (overRateLimit(user.id)) return Response.json({ error: "Too many requests. Please wait a minute and try again." }, { status: 429 });
      const holder = myEmail ? await myHolder() : null;
      if (!holder || holder.status !== "active") return Response.json({ error: "Verify your identity before funding your account." }, { status: 403 });
      const amount = round2(input.amount);
      if (!(amount > 0) || amount > 1000000) return Response.json({ error: "Enter the amount you sent." }, { status: 400 });
      const method = DEPOSIT_METHODS.includes(input.method) ? input.method : "";
      if (!method) return Response.json({ error: "Choose how you paid." }, { status: 400 });
      const wallet = await walletOf(context, myEmail);
      if (wallet.entries.filter((entry) => entry.kind === "deposit" && entry.status === "pending").length >= 5) {
        return Response.json({ error: "You already have 5 deposits waiting to be confirmed. Please wait for them first." }, { status: 409 });
      }
      const proof = await proofFields(input.proofToken, myEmail, input.proofName);
      if (proof === null) return Response.json({ error: "The proof of payment could not be attached. Please add it again." }, { status: 400 });
      const created = await addEntry(context, {
        owner_email: myEmail, client_name: holder.full_name || user.full_name || "", kind: "deposit", status: "pending",
        amount, reported_amount: amount, method, reference: clean(input.reference, 120), note: clean(input.note, 300), reported_by: "client",
        ...proof,
      });
      return Response.json({ entry: publicEntry(created) });
    }

    if (action === "wallet_overview") {
      // Every client with an account or a verified card user, with balances,
      // plus the deposits clients reported that wait for review.
      const db = context.entities;
      const entries = rowsFrom(await db.AccountEntry.list({ sort: "-created_date", limit: 2000 }));
      const holds = rowsFrom(await db.CardRequest.filter({ status: "pending" }, { limit: 200 }));
      const holders = rowsFrom(await db.Cardholder.list({ limit: 500 }));
      const clients = new Map();
      const touch = (email, name) => {
        const key = String(email || "").toLowerCase();
        if (!key) return null;
        if (!clients.has(key)) clients.set(key, { email: key, name: name || "", balance: 0, held: 0, deposited: 0, pending_deposits: 0, last_activity: "", verified: false });
        const row = clients.get(key);
        if (!row.name && name) row.name = name;
        return row;
      };
      for (const holder of holders) {
        const row = touch(holder.owner_email, holder.full_name);
        if (row && holder.status === "active") row.verified = true;
      }
      for (const entry of entries) {
        const row = touch(entry.owner_email, entry.client_name);
        if (!row) continue;
        if (entry.status === "completed") row.balance += Number(entry.amount) || 0;
        if (entry.status === "completed" && entry.kind === "deposit") row.deposited += Math.max(0, Number(entry.amount) || 0);
        if (entry.status === "pending" && entry.kind === "deposit") row.pending_deposits += 1;
        const when = entry.recorded_at || entry.created_date || "";
        if (when > row.last_activity) row.last_activity = when;
      }
      for (const hold of holds) {
        const row = touch(hold.owner_email, hold.client_name);
        if (row) row.held += Number(hold.amount) || 0;
      }
      const overviewSettings = await programmeSettings(context);
      const list = [...clients.values()].map((row) => {
        const standing = tierStanding(row.deposited, overviewSettings);
        return { ...row, balance: round2(row.balance), held: round2(row.held), available: round2(row.balance - row.held), deposited: round2(row.deposited), tier: standing.tier, next_tier: standing.next_tier };
      })
        .sort((a, b) => (b.last_activity || "").localeCompare(a.last_activity || "") || a.email.localeCompare(b.email));
      const pending = entries.filter((entry) => entry.status === "pending" && entry.kind === "deposit")
        .map((entry) => ({ ...publicEntry(entry), owner_email: entry.owner_email, client_name: entry.client_name || "", reported_by: entry.reported_by || "" }));
      return Response.json({
        clients: list, pending_deposits: pending,
        totals: { held_for_clients: round2(list.reduce((sum, row) => sum + row.balance, 0)), pending_count: pending.length },
      });
    }

    if (action === "wallet_client") {
      const email = clean(input.ownerEmail, 254).toLowerCase();
      if (!EMAIL.test(email)) return Response.json({ error: "Choose a client." }, { status: 400 });
      const wallet = await walletOf(context, email);
      return Response.json({
        email, balance: wallet.balance, held: wallet.held, available: wallet.available,
        ...tierStanding(wallet.deposited, await programmeSettings(context)),
        entries: wallet.entries.map((entry) => ({ ...publicEntry(entry), admin_note: entry.admin_note || "", recorded_by: entry.recorded_by || "", reported_by: entry.reported_by || "", reported_amount: entry.reported_amount ?? null, card_id: entry.card_id || "" })),
        holds: wallet.holds.map((row) => ({ id: row.id, amount: row.amount, requested_at: row.requested_at || row.created_date || "" })),
      });
    }

    if (action === "wallet_record") {
      // A deposit received (transfer, cash…) or a correction, entered by an administrator.
      const email = clean(input.ownerEmail, 254).toLowerCase();
      if (!EMAIL.test(email)) return Response.json({ error: "Choose the client the money belongs to." }, { status: 400 });
      const kind = input.kind === "adjustment" ? "adjustment" : "deposit";
      const amount = round2(input.amount);
      const note = clean(input.note, 300);
      if (kind === "deposit") {
        if (!(amount > 0) || amount > 1000000) return Response.json({ error: "Enter the amount received." }, { status: 400 });
        if (!DEPOSIT_METHODS.includes(input.method)) return Response.json({ error: "Choose how the client paid." }, { status: 400 });
      } else {
        if (!amount || Math.abs(amount) > 1000000) return Response.json({ error: "Enter the correction: positive adds to the balance, negative takes from it." }, { status: 400 });
        if (note.length < 3) return Response.json({ error: "Give a reason for the correction; the client sees it." }, { status: 400 });
        const wallet = await walletOf(context, email);
        if (wallet.available + amount < 0) return Response.json({ error: `That would take the available balance below zero (available ${wallet.available.toFixed(2)} USD).` }, { status: 409 });
      }
      const proof = kind === "deposit" ? await proofFields(input.proofToken, String(user.email || "").toLowerCase(), input.proofName) : {};
      if (proof === null) return Response.json({ error: "The proof of payment could not be attached. Please add it again." }, { status: 400 });
      const holder = rowsFrom(await context.entities.Cardholder.filter({ owner_email: email }, { limit: 1 }))[0];
      const created = await addEntry(context, {
        ...proof,
        owner_email: email, client_name: holder?.full_name || clean(input.clientName, 120), kind, status: "completed", amount,
        method: kind === "deposit" ? input.method : "", reference: clean(input.reference, 120), note, admin_note: clean(input.adminNote, 500),
        reported_by: "admin", recorded_by: String(user.email || ""),
      });
      const wallet = await walletOf(context, email);
      if (kind === "deposit") await announceTier(context, email, round2(wallet.deposited - amount), wallet.deposited);
      await notifyClient(context, email, kind === "deposit"
        ? { kind: "funds", tone: "success", title: "Funds added to your account", body: `${amount.toFixed(2)} USD received${input.method === "cash" ? " in cash" : ""}. Available now: ${wallet.available.toFixed(2)} USD.`, link: "/account", key: `deposit-recorded:${created.id}` }
        : { kind: "funds", tone: "info", title: "Your balance was corrected", body: `${amount > 0 ? "+" : "−"}${Math.abs(amount).toFixed(2)} USD: ${note}`, link: "/account", key: `adjustment:${created.id}` });
      return Response.json({ entry: publicEntry(created), balance: wallet.balance, available: wallet.available });
    }

    if (action === "wallet_review") {
      // Confirm (possibly for the amount actually received) or reject a deposit a client reported.
      const entry = await context.entities.AccountEntry.get(clean(input.entryId, 64)).catch(() => null);
      if (!entry || entry.kind !== "deposit") return Response.json({ error: "Deposit not found." }, { status: 404 });
      if (entry.status !== "pending") return Response.json({ error: `This deposit is already ${entry.status}.` }, { status: 409 });
      const reviewed = { recorded_by: String(user.email || ""), recorded_at: new Date().toISOString(), admin_note: clean(input.adminNote, 500) };
      if (input.decision === "reject") {
        const reason = clean(input.note, 300);
        if (reason.length < 3) return Response.json({ error: "Tell the client why (at least 3 characters)." }, { status: 400 });
        await context.entities.AccountEntry.update(entry.id, { ...reviewed, status: "rejected", note: reason });
        await notifyClient(context, entry.owner_email, { kind: "funds", tone: "warning", title: "Deposit not received", body: `${round2(entry.amount).toFixed(2)} USD: ${reason}`, link: "/account", key: `deposit-rejected:${entry.id}` });
        return Response.json({ ok: true, status: "rejected" });
      }
      if (input.decision !== "confirm") return Response.json({ error: "Choose confirm or reject." }, { status: 400 });
      const amount = round2(input.amount ?? entry.amount);
      if (!(amount > 0) || amount > 1000000) return Response.json({ error: "Enter the amount actually received." }, { status: 400 });
      await context.entities.AccountEntry.update(entry.id, {
        ...reviewed, status: "completed", amount, reported_amount: entry.reported_amount ?? entry.amount,
        ...(amount !== round2(entry.amount) ? { note: `Received ${amount.toFixed(2)} USD (you reported ${round2(entry.amount).toFixed(2)} USD).` } : {}),
      });
      const wallet = await walletOf(context, entry.owner_email);
      await announceTier(context, entry.owner_email, round2(wallet.deposited - amount), wallet.deposited);
      await notifyClient(context, entry.owner_email, { kind: "funds", tone: "success", title: "Deposit confirmed", body: `${amount.toFixed(2)} USD was added to your balance. Available now: ${wallet.available.toFixed(2)} USD.`, link: "/account", key: `deposit-confirmed:${entry.id}` });
      return Response.json({ ok: true, status: "completed", balance: wallet.balance, available: wallet.available });
    }

    if (action === "store_deposit_proof") {
      // A receipt photo or PDF for a deposit; returned only as a token bound to this account.
      if (overRateLimit(user.id)) return Response.json({ error: "Too many requests. Please wait a minute and try again." }, { status: 429 });
      const data = String(input.dataBase64 || "").replace(/^data:[^,]*,/, "");
      let bytes;
      try { bytes = Uint8Array.from(atob(data), (c) => c.charCodeAt(0)); } catch { bytes = new Uint8Array(); }
      if (!bytes.length) return Response.json({ error: "The file could not be read." }, { status: 400 });
      if (bytes.length > MAX_PROOF_BYTES) return Response.json({ error: "The proof must be 6 MB or smaller." }, { status: 400 });
      const kind = proofKind(bytes);
      if (!kind) return Response.json({ error: "Add a photo (JPG or PNG) or a PDF." }, { status: 400 });
      const ext = kind === "application/pdf" ? "pdf" : kind === "image/png" ? "png" : "jpg";
      const base = clean(input.fileName, 80).replace(/\.[^.]*$/, "").replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^[^A-Za-z0-9]+/, "") || "proof";
      const { file_uri: fileUri } = await context.files.uploadPrivateFile({ file: new File([bytes], `${base}.${ext}`, { type: kind }) });
      if (!PROOF_FILE.test(String(fileUri || ""))) return Response.json({ error: "The file could not be saved. Please try again." }, { status: 502 });
      const proofToken = await signPhotoToken(proofSubject(myEmail), fileUri);
      if (!proofToken) return Response.json({ error: "File storage is temporarily unavailable. Please contact support." }, { status: 503 });
      return Response.json({ proof_token: proofToken, type: kind });
    }

    if (action === "my_deposit_proof" || action === "deposit_proof") {
      // A short-lived link to a deposit's proof: the client sees only their own.
      const entry = await context.entities.AccountEntry.get(clean(input.entryId, 64)).catch(() => null);
      const own = entry && String(entry.owner_email || "").toLowerCase() === myEmail;
      if (!entry || (action === "my_deposit_proof" && !own) || !entry.proof_file_uri || !PROOF_FILE.test(entry.proof_file_uri)) {
        return Response.json({ error: "No proof of payment for this deposit." }, { status: 404 });
      }
      const { signed_url: url } = await context.files.createSignedUrl({ file_uri: entry.proof_file_uri, expires_in: 300 });
      return Response.json({ url, type: entry.proof_type || "", name: entry.proof_name || "" });
    }

    if (action === "store_id_photo") {
      // One ID photo for the client's own application: stored in the app's
      // private files here, handed back only as a token bound to this account.
      if (overRateLimit(user.id)) return Response.json({ error: "Too many requests. Please wait a minute and try again." }, { status: 429 });
      const data = String(input.dataBase64 || "").replace(/^data:[^,]*,/, "");
      let bytes;
      try { bytes = Uint8Array.from(atob(data), (c) => c.charCodeAt(0)); } catch { bytes = new Uint8Array(); }
      if (!bytes.length) return Response.json({ error: "The photo could not be read." }, { status: 400 });
      if (bytes.length > 6 * 1024 * 1024) return Response.json({ error: "Each ID photo must be 6 MB or smaller." }, { status: 400 });
      const kind = imageKind(bytes);
      if (!kind) return Response.json({ error: "ID photos must be JPG or PNG." }, { status: 400 });
      const fileName = clean(input.fileName, 80).replace(/[^A-Za-z0-9._-]+/g, "-") || (kind === "image/png" ? "id.png" : "id.jpg");
      const { file_uri: fileUri } = await context.files.uploadPrivateFile({ file: new File([bytes], fileName, { type: kind }) });
      if (!isPrivateAppFile(fileUri)) return Response.json({ error: "The photo could not be saved. Please try again." }, { status: 502 });
      const photoToken = await signPhotoToken(myEmail, fileUri);
      if (!photoToken) return Response.json({ error: "Photo storage is temporarily unavailable. Please contact support." }, { status: 503 });
      return Response.json({ photo_token: photoToken });
    }

    if (action === "submit_registration") {
      if (overRateLimit(user.id)) return Response.json({ error: "Too many requests. Please wait a minute and try again." }, { status: 429 });
      const existing = await myApplications();
      if (existing.some((app) => app.status === "submitted")) {
        return Response.json({ error: "Your verification is already waiting for review." }, { status: 409 });
      }
      if (existing.some((app) => app.status === "approved")) {
        return Response.json({ error: "Your verification was already approved." }, { status: 409 });
      }
      // The application belongs to the signed-in account: its email is the
      // login email (PhotonPay allows 40 characters; longer ones need a mobile).
      const accountEmail = myEmail.length <= 40 ? myEmail : "";
      // The client's own device: PhotonPay receives it when their card is issued.
      const deviceCountry = clientCountry(req, input.deviceCountry);
      if (!deviceCountry) return Response.json({ error: "Select the country you are in now." }, { status: 400 });
      const { problems, fields } = validateHolder({ ...input, email: accountEmail });
      // Only photos this function stored for this account are accepted.
      const frontUri = await readPhotoToken(input.frontPhotoToken, myEmail);
      const backUri = await readPhotoToken(input.backPhotoToken, myEmail);
      if (!frontUri) problems.push("Add a photo of the front of the ID (passport photo page)");
      if (fields.certType !== "passport" && !backUri) problems.push("Add a photo of the back of the ID");
      if (problems.length) return Response.json({ error: problems.join(". ") + ".", problems }, { status: 400 });
      const created = await context.entities.CardholderApplication.create({
        owner_email: myEmail, status: "submitted", submitted_at: new Date().toISOString(),
        first_name: fields.firstName, last_name: fields.lastName, date_of_birth: fields.dateOfBirth,
        nationality: fields.nationalityCountryCode, email: fields.email,
        mobile_prefix: fields.mobilePrefix, mobile: fields.mobile,
        address_line: fields.residentialAddress, city: fields.residentialCity, state: fields.residentialState,
        postal_code: fields.residentialPostalCode, country: fields.residentialCountryCode,
        cert_type: fields.certType, cert_id: fields.certId, cert_country: fields.certCountryCode,
        front_file_uri: frontUri, back_file_uri: fields.certType !== "passport" ? backUri : "",
        // No device address is recorded here: the only one a client could
        // supply is caller-claimed, and PhotonPay risk input must not be.
        device_ip: "", device_country: deviceCountry,
      });
      return Response.json({ application: publicApplication(created) });
    }

    // ---- Administrator review of client applications (no PhotonPay call).
    if (action === "reject_application") {
      const application = await context.entities.CardholderApplication.get(clean(input.applicationId, 64)).catch(() => null);
      if (!application) return Response.json({ error: "Application not found." }, { status: 404 });
      if (application.status !== "submitted") return Response.json({ error: `This application is already ${application.status}.` }, { status: 409 });
      const note = clean(input.note, 500);
      if (!note) return Response.json({ error: "Tell the client why, so they can correct and resubmit." }, { status: 400 });
      await context.entities.CardholderApplication.update(application.id, {
        status: "rejected", review_note: note, reviewed_by: user.email, reviewed_at: new Date().toISOString(),
        // Rejected applications are never sent; drop the full ID number.
        cert_id: maskIdNumber(application.cert_id),
      });
      await notifyClient(context, application.owner_email, { kind: "verification", tone: "warning", title: "Your verification needs changes", body: note, link: "/verification", key: `application-rejected:${application.id}` });
      return Response.json({ ok: true, application_status: "rejected" });
    }

    if (action === "application_photo") {
      const application = await context.entities.CardholderApplication.get(clean(input.applicationId, 64)).catch(() => null);
      if (!application) return Response.json({ error: "Application not found." }, { status: 404 });
      const uri = input.side === "back" ? application.back_file_uri : application.front_file_uri;
      if (!uri) return Response.json({ error: "No photo for that side." }, { status: 404 });
      // Short-lived link so the administrator can check the photo before approving.
      const { signed_url: url } = await context.files.createSignedUrl({ file_uri: uri, expires_in: 120 });
      return Response.json({ url });
    }

    // Provider identifiers are never accepted from customers. Resolve a trusted,
    // admin-managed local card first, then authorize its assigned account.
    let record = null;
    if (cardActions.includes(action) || adminCardActions.includes(action) || action === "assign") {
      const recordId = clean(input.recordId, 64);
      if (!recordId) return Response.json({ error: "A local card record is required" }, { status: 400 });
      record = await context.entities.Card.get(recordId).catch(() => null);
      if (!record || (!admin && (!record.owner_email || record.owner_email.toLowerCase() !== String(user.email || "").toLowerCase()))) {
        return Response.json({ error: "You do not have access to this card" }, { status: 403 });
      }
    }

    if (record?.form_factor && record.form_factor !== "virtual_card") {
      return Response.json({ error: "This programme supports virtual cards only." }, { status: 409 });
    }

    if (action === "assign") {
      const ownerEmail = clean(input.ownerEmail, 254).toLowerCase();
      if (ownerEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(ownerEmail)) {
        return Response.json({ error: "Enter a valid account email" }, { status: 400 });
      }
      // Revoke the previous assignment before moving any activity to another
      // account. A failed migration leaves the card restricted to admins.
      await context.entities.Card.update(record.id, { owner_email: "" });
      let cursor = null;
      do {
        const page = await context.entities.CardTransaction.filter(
          { card_id: record.id },
          { limit: 100, ...(cursor ? { cursor } : {}) },
        );
        const rows = Array.isArray(page) ? page : page.items || [];
        await Promise.all(rows.map((item) => context.entities.CardTransaction.update(item.id, { owner_email: ownerEmail })));
        cursor = !Array.isArray(page) && page.has_more ? page.next_cursor : null;
      } while (cursor);
      await context.entities.Card.update(record.id, { owner_email: ownerEmail });
      return Response.json({ ok: true, owner_email: ownerEmail });
    }

    if (record && !record.photon_card_id && action !== "resolve") {
      return Response.json({ error: "This card is not available for live controls yet." }, { status: 409 });
    }

    let issueHolder = null;
    let ownerEmail = "";
    if (action === "issue") {
      if (input.cardFormFactor && input.cardFormFactor !== "virtual_card") {
        return Response.json({ error: "Z8 currently issues virtual cards only." }, { status: 400 });
      }
      // PhotonPay assigns the card BIN itself; the programme only chooses the
      // currency, so a BIN is never accepted from the browser.
      if (!CURRENCIES.includes(clean(input.cardCurrency, 3) || "USD")) {
        return Response.json({ error: "PhotonPay issues these virtual cards in USD only." }, { status: 400 });
      }
      const localId = clean(input.cardholderRecordId, 64);
      if (!localId) return Response.json({ error: "Sync and select a PhotonPay cardholder before issuing." }, { status: 400 });
      issueHolder = await context.entities.Cardholder.get(localId).catch(() => null);
      if (!issueHolder?.photon_cardholder_id) {
        return Response.json({ error: "This client is not linked to a PhotonPay cardholder. Sync clients first." }, { status: 409 });
      }
      ownerEmail = clean(input.ownerEmail, 254).toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(ownerEmail)) {
        return Response.json({ error: "Enter the client's Z8 account email." }, { status: 400 });
      }
    }
    // Provider-backed calls cost the programme quota, so each account may only
    // make a limited number of them per minute.
    if (overRateLimit(user.id)) {
      return Response.json({ error: "Too many card requests. Please wait a minute and try again." }, { status: 429 });
    }

    const cfg = { ...getConfig(context), source: "photonpayCards" };
    const programme = {
      master_account_email: cfg.masterAccountEmail || "",
      account_model: "merchant_cardholders",
      card_form_factor: "virtual_card",
    };

    if (action === "status") {
      if (!cfg.configured) {
        return Response.json({
          configured: false,
          ...programme,
          env: cfg.env,
          connected: false,
          signing: Boolean(cfg.privateKey),
          relay: getRelayConfig().configured,
          message: "Add your PhotonPay App ID and App Secret to connect the card programme.",
        });
      }
      try {
        const live = await resolveConfig(cfg);
        return Response.json({
          configured: true,
          ...programme,
          env: live.env,
          connected: true,
          signing: Boolean(cfg.privateKey),
          relay: getRelayConfig().configured,
          autodetected: !cfg.envExplicit && live.env !== cfg.env,
        });
      } catch (error) {
        return Response.json({ configured: true, ...programme, env: cfg.env, connected: false, signing: Boolean(cfg.privateKey), relay: getRelayConfig().configured, message: error.message,
          error_code: error.providerCode || "", http_status: error.httpStatus || null,
          failure_stage: error.stage || "connection", reference: error.reference || "",
        });
      }
    }

    if (!cfg.configured) {
      return Response.json({ error: admin ? "Connect the card provider in admin settings first." : "Card controls are temporarily unavailable. Please contact your administrator." }, { status: 400 });
    }

    const live = await resolveConfig(cfg);

    if (action === "approve_card_request" || action === "reject_card_request") {
      const row = await context.entities.CardRequest.get(clean(input.requestId, 64)).catch(() => null);
      if (!row) return Response.json({ error: "Card request not found." }, { status: 404 });
      if (row.status !== "pending") return Response.json({ error: `This request is already ${row.status}.` }, { status: 409 });
      const reviewed = { reviewed_by: String(user.email || ""), reviewed_at: new Date().toISOString() };
      if (action === "reject_card_request") {
        const reason = clean(input.note, 300);
        if (reason.length < 3) return Response.json({ error: "Tell the client why (at least 3 characters)." }, { status: 400 });
        await context.entities.CardRequest.update(row.id, { ...reviewed, status: "rejected", review_note: reason });
        await notifyClient(context, row.owner_email, { kind: "card_request", tone: "warning", title: "Card request not approved", body: `${reason} The ${round2(row.amount).toFixed(2)} USD set aside is available again.`, link: "/cards", key: `card-request-rejected:${row.id}` });
        return Response.json({ ok: true, status: "rejected" });
      }
      const holder = await context.entities.Cardholder.get(row.cardholder_record_id).catch(() => null);
      if (!holder?.photon_cardholder_id || holder.status !== "active") {
        return Response.json({ error: "This client is no longer approved at PhotonPay, so no card can be created." }, { status: 409 });
      }
      const settings = await programmeSettings(context);
      const min = minOpeningAmount(settings);
      const amount = Math.round(Number(input.amount ?? row.amount) * 100) / 100;
      if (!Number.isFinite(amount) || amount < min) return Response.json({ error: `The opening amount must be at least ${min.toFixed(2)} USD.` }, { status: 400 });
      if (amount > 100000) return Response.json({ error: "Enter an amount up to 100,000 USD." }, { status: 400 });
      // The request's own hold counts towards what it may use.
      const clientWallet = await walletOf(context, row.owner_email);
      const covered = round2(clientWallet.available + (Number(row.amount) || 0));
      if (amount > covered) {
        return Response.json({ error: `The client's available balance is ${covered.toFixed(2)} USD, less than ${amount.toFixed(2)} USD. Record their deposit under Client funds first, or load less.` }, { status: 409 });
      }
      const ipAddress = adminDeviceIp(req);
      const gpsCountry = clientCountry(req, input.gpsCountry);
      if (!ipAddress) return Response.json({ error: "Your device's public IP address could not be determined, which PhotonPay requires to create a card. Try again from another network." }, { status: 400 });
      if (!gpsCountry) return Response.json({ error: "Select the country you are in now." }, { status: 400 });
      if (cardRequestsInFlight.has(holder.id)) return Response.json({ error: "A card for this client is already being created." }, { status: 409 });
      cardRequestsInFlight.add(holder.id);
      try {
        await context.entities.CardRequest.update(row.id, { last_error: "" });
        const result = await issueRegularCard(context, live, holder, { ipAddress, gpsCountry, amount, purpose: row.purpose || "", purposeDetail: row.purpose_detail || "", tier: row.tier || "" });
        if (result.status !== "requested") {
          // The request stays pending so it can be approved again once fixed.
          await context.entities.CardRequest.update(row.id, { last_error: String(result.note || "").slice(0, 500) });
          return Response.json({ error: result.note || "PhotonPay could not create the card." }, { status: 502 });
        }
        await context.entities.CardRequest.update(row.id, {
          ...reviewed, status: "approved", approved_amount: amount, card_record_id: result.card_record_id, provider_request_id: result.request_id,
        });
        await addEntry(context, {
          owner_email: row.owner_email, client_name: row.client_name || holder.full_name || "", kind: "card_opening", status: "completed",
          amount: -amount, card_id: result.card_record_id, card_request_id: row.id, note: "Opening balance of your new card",
          reported_by: "admin", recorded_by: String(user.email || ""),
        });
        await notifyClient(context, row.owner_email, { kind: "card_request", tone: "success", title: "Card request approved", body: `Your card is being created with ${amount.toFixed(2)} USD. We'll tell you when it's ready.`, link: "/cards", key: `card-request-approved:${row.id}` });
        return Response.json({ ok: true, status: "approved", card_record_id: result.card_record_id, amount });
      } finally {
        cardRequestsInFlight.delete(holder.id);
      }
    }

    if (action === "upload_id_image") {
      // One ID photo for cardholder registration, sent straight to PhotonPay.
      // Z8 keeps only the returned file key, never the image.
      const mimeType = clean(input.mimeType, 20).toLowerCase();
      if (!["image/jpeg", "image/png"].includes(mimeType)) {
        return Response.json({ error: "ID photos must be JPG or PNG." }, { status: 400 });
      }
      const data = String(input.dataBase64 || "").replace(/^data:[^,]*,/, "");
      let bytes;
      try { bytes = Uint8Array.from(atob(data), (c) => c.charCodeAt(0)); } catch { bytes = new Uint8Array(); }
      if (!bytes.length) return Response.json({ error: "The ID photo could not be read." }, { status: 400 });
      if (bytes.length > 6 * 1024 * 1024) return Response.json({ error: "Each ID photo must be 6 MB or smaller." }, { status: 400 });
      const jpeg = bytes[0] === 0xff && bytes[1] === 0xd8;
      const png = bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47;
      if (!(jpeg || png)) return Response.json({ error: "The file is not a JPG or PNG image." }, { status: 400 });
      const fileKey = await photonUpload(live, "issuing_cardholder_identity_certificate", bytes,
        clean(input.fileName, 80) || (png ? "id.png" : "id.jpg"), png ? "image/png" : "image/jpeg");
      return Response.json({ file_key: fileKey });
    }

    if (action === "add_holder") {
      const { problems, fields } = validateHolder(input);
      const portrait = clean(input.portrait, 64);
      const reverseSide = clean(input.reverseSide, 64);
      if (!portrait) problems.push("Upload the front of the ID (passport photo page)");
      if (fields.certType !== "passport" && !reverseSide) problems.push("Upload the back of the ID");
      if (problems.length) return Response.json({ error: problems.join(". ") + ".", problems }, { status: 400 });
      // The administrator's own device stands in for the client's when the card
      // is issued automatically for a client registered here.
      const deviceCountry = clientCountry(req, input.deviceCountry);
      if (!deviceCountry) return Response.json({ error: "Select the country you are in now (PhotonPay needs it when the client's card is issued)." }, { status: 400 });
      const { saved, data } = await registerWithPhotonPay(context, live, fields, portrait, reverseSide, {
        ownerEmail: clean(input.ownerEmail, 254) || fields.email, deviceIp: adminDeviceIp(req), deviceCountry,
      });
      return Response.json(registrationResult(saved, data));
    }

    if (action === "approve_application") {
      // An administrator approved a client's own application: only now do its
      // details and ID photos go to PhotonPay.
      const application = await context.entities.CardholderApplication.get(clean(input.applicationId, 64)).catch(() => null);
      if (!application) return Response.json({ error: "Application not found." }, { status: 404 });
      if (application.status !== "submitted") {
        return Response.json({ error: `This application is already ${application.status}.` }, { status: 409 });
      }
      const fields = applicationFields(application);
      const { problems } = validateHolder(fieldsAsInput(fields));
      if (problems.length) return Response.json({ error: `The application is incomplete: ${problems.join(". ")}.` }, { status: 400 });
      try {
        const portrait = await forwardPrivatePhoto(context, live, application.front_file_uri, "front");
        const reverseSide = fields.certType !== "passport" ? await forwardPrivatePhoto(context, live, application.back_file_uri, "back") : "";
        const { saved, data } = await registerWithPhotonPay(context, live, fields, portrait, reverseSide, {
          ownerEmail: application.owner_email, deviceIp: application.device_ip, deviceCountry: application.device_country,
        });
        await context.entities.CardholderApplication.update(application.id, {
          status: "approved", reviewed_by: user.email, reviewed_at: new Date().toISOString(),
          photon_cardholder_id: clean(data.cardholderId, 64), cardholder_record_id: saved.id,
          // The full ID number has served its purpose; keep only the last four.
          cert_id: maskIdNumber(fields.certId), last_error: "",
        });
        await notifyClient(context, application.owner_email, {
          kind: "verification", tone: "info", title: "Your details were approved",
          body: saved.status === "active" ? "You're verified. Add funds to your account to request your card." : "Our card issuer is doing a final identity check. We'll let you know when it clears.",
          link: saved.status === "active" ? "/cards" : "/verification", key: `application-approved:${application.id}`,
        });
        return Response.json({ ...registrationResult(saved, data), application_status: "approved" });
      } catch (error) {
        // Stays "submitted" so the administrator can fix the cause and retry.
        await context.entities.CardholderApplication.update(application.id, { last_error: String(error?.message || error).slice(0, 500) });
        throw error;
      }
    }


    if (action === "resolve") {
      // Links a card applied for with openCardHalo once PhotonPay has created it.
      const result = await resolveIssuedCard(context, live, record);
      return Response.json({
        state: result.state,
        status: result.record.status,
        last4: result.record.last4 || "",
        masked_number: result.record.masked_number || "",
        linked: Boolean(result.record.photon_card_id),
      });
    }


    if (action === "sync_holders") {
      const pageIndex = Math.max(1, Math.floor(numberOrUndefined(input.pageIndex) || 1));
      const pageSize = 100;
      const json = await photonRequest(live, "/vcc/openApi/v4/pagingVccCardholder", {
        query: { pageIndex, pageSize },
      });
      const source = rowsOf(json);
      const holders = [];
      for (const row of source) {
        const saved = await saveHolder(context, row, live);
        if (saved) holders.push(saved);
      }
      const total = Number(json.total ?? json.data?.total);
      const hasMore = Number.isFinite(total) ? pageIndex * pageSize < total : source.length === pageSize;
      return Response.json({ synced: holders.length, page_index: pageIndex, has_more: hasMore });
    }

    if (action === "balance") {
      // The USD PhotonPay balance that Regular cards (type recharge) are funded from.
      const funding = (await photonRequest(live, "/wallet/openApi/v4/account/single", { query: { currency: "USD", accountType: "FT10001" } })).data || {};
      return Response.json({ currency: "USD", account: clean(funding.accountNo, 64), available: Number(funding.realTimeBalance ?? 0), as_of: clean(funding.returnedAt, 40), environment: live.env });
    }

    // Legacy: getCardBin is no longer in PhotonPay's API documentation and
    // openCardHalo chooses the BIN itself. Kept for compatibility, not shown.
    if (action === "bins") {
      const json = await photonRequest(live, "/vcc/openApi/v4/getCardBin", {
        query: { cardCurrency: clean(input.currency, 3) || undefined, cardFormFactor: "virtual_card" },
      });
      const list = json.data || json.rows || [];
      return Response.json({ bins: Array.isArray(list) ? list : list.list || [] });
    }

    if (action === "list") {
      const json = await photonRequest(live, "/vcc/openApi/v4/pagingVccCard", {
        query: {
          cardFormFactor: "virtual_card",
          pageIndex: numberOrUndefined(input.pageIndex) || 1,
          pageSize: numberOrUndefined(input.pageSize) || 20,
          cardStatus: clean(input.status, 30) || undefined,
          nickname: clean(input.nickname, 50) || undefined,
        },
      });
      const data = json.data || {};
      const rows = Array.isArray(data) ? data : data.list || data.rows || [];
      return Response.json({ cards: rows.map(pickCard), total: data.total || rows.length });
    }

    if (action === "detail") {
      const cardId = record.photon_card_id;
      if (!cardId) return Response.json({ error: "cardId is required" }, { status: 400 });
      // Full card details belong to the card's owner (PCI DSS need-to-know).
      // An administrator may reveal them on another account's card only with a
      // stated reason, and every such view is recorded in the card's activity,
      // where the client sees it.
      const ownsCard = Boolean(record.owner_email) && record.owner_email.toLowerCase() === String(user.email || "").toLowerCase();
      const adminView = admin && !ownsCard;
      const viewReason = clean(input.reason, 301);
      if (adminView && (viewReason.length < 10 || viewReason.length > 300)) {
        return Response.json({ error: "Give a reason (10 to 300 characters) to view this client's card details. The view is recorded in the card's activity.", reason_required: true }, { status: 403 });
      }
      if (adminView) {
        await context.entities.CardTransaction.create({
          kind: "event", event: "Card details viewed by administrator", card_id: record.id, card_last4: record.last4,
          card_nickname: record.nickname, amount: 0, currency: record.currency, status: "completed",
          occurred_at: new Date().toISOString(), owner_email: record.owner_email || "",
          note: `${user.email}: ${viewReason}`,
        });
      }
      // An automatically issued card stays locked for its owner until it is funded.
      if (!adminView && record.auto_issued && !record.funded_at) {
        return Response.json({ error: "Your card is ready. Its details unlock once your account is funded.", not_funded: true }, { status: 403 });
      }
      const json = await photonRequest(live, "/vcc/openApi/v4/getCardDetail", { query: { cardId } });
      // Card detail does not include the CVV; PhotonPay serves it from a separate endpoint.
      // getCvv is PhotonPay's sensitive-data endpoint: it returns the full card
      // number, CVV and expiry, which getCardDetail may only give masked.
      let cvvError = "";
      const cvvJson = await photonRequest(live, "/vcc/openApi/v4/getCvv", { query: { cardId } })
        .catch((error) => { cvvError = error.message || "unavailable"; return {}; });
      const secret = cvvJson?.data || {};
      const merged = { ...(json.data || {}) };
      if (secret.cardNo && !String(secret.cardNo).includes("*")) merged.cardNo = secret.cardNo;
      if (secret.expirationDate && !String(secret.expirationDate).includes("*")) merged.expirationDate = secret.expirationDate;
      const card = pickCard({ ...merged, cvv: secret.cvv || "" });
      // A masked number is not a revealed one.
      if (/\*/.test(card.card_no)) card.card_no = "";
      if (/\*/.test(card.expiry)) card.expiry = "";
      // Keep the local balance and status in step with PhotonPay while we have them.
      await refreshCardRecord(context, record, json.data || {}).catch(() => null);
      // Everyone receives only the details needed to use the card, without
      // provider or cardholder identifiers.
      return Response.json({ card: {
        card_no: card.card_no, cvv: card.cvv, expiry: card.expiry,
        last4: card.last4, masked_number: card.masked_number,
        scheme: card.scheme, currency: card.currency,
      }, ...(!card.cvv ? { cvv_unavailable: true, cvv_error: cvvError ? "PhotonPay did not return the CVV." : "" } : {}) });
    }


    if (action === "refresh") {
      // PhotonPay's live view of the card for the card page: balance, status,
      // limit type and whether the CVV is blocked. No card number, CVV or expiry.
      const json = await photonRequest(live, "/vcc/openApi/v4/getCardDetail", { query: { cardId: record.photon_card_id } });
      const data = json.data || {};
      const updated = await refreshCardRecord(context, record, data);
      return Response.json({
        balance: updated.balance ?? null,
        status: updated.status,
        transaction_limit_type: updated.transaction_limit_type || "",
        cvv_blocked: String(data.cvvBlocked || "").toUpperCase() === "Y",
        provider_status: String(data.cardStatus || ""),
      });
    }

    if (action === "issue") {
      // Query PhotonPay again immediately before the money-related operation.
      // A local "active" label is never proof of provider approval.
      const remote = await photonRequest(live, "/vcc/openApi/v4/pagingVccCardholder", {
        query: { cardholderId: issueHolder.photon_cardholder_id, pageIndex: 1, pageSize: 100 },
      });
      const holder = rowsOf(remote).find(row => row.cardholderId === issueHolder.photon_cardholder_id && !row.matrixAccount);
      if (!holder) return Response.json({ error: "Cardholder not found under the connected merchant account. Sync clients and check the main account credentials." }, { status: 409 });
      const refreshed = await saveHolder(context, holder, live, issueHolder);
      if (refreshed.status !== "active") {
        return Response.json({
          error: "PhotonPay cardholder approval is required before issuance.",
          review_status: refreshed.review_status,
          provider_status: refreshed.provider_status,
        }, { status: 409 });
      }

      const ipAddress = adminDeviceIp(req);
      const gpsCountry = clientCountry(req, input.gpsCountry);
      if (!ipAddress) {
        return Response.json({ error: "Your device's public IP address could not be determined, which PhotonPay requires to issue a card. Try again from another network." }, { status: 400 });
      }
      if (!gpsCountry) {
        return Response.json({ error: "Select the country you are issuing from (PhotonPay requires it)." }, { status: 400 });
      }
      const limited = clean(input.transactionLimitType, 20) === "limited";
      const cardType = clean(input.cardType, 20) === "recharge" ? "recharge" : "share";
      // Regular cards (type recharge) are funded at issue from the programme's USD
      // PhotonPay balance, so PhotonPay needs that account and an amount.
      const rechargeAmount = Math.round((Number(input.rechargeAmount) || 0) * 100) / 100;
      if (cardType === "recharge" && !(rechargeAmount > 0)) {
        return Response.json({ error: "Enter the opening balance (USD) for this Regular card." }, { status: 400 });
      }
      const fundingJson = await photonRequest(live, "/wallet/openApi/v4/account/single", {
        query: { currency: "USD", accountType: "FT10001" },
      });
      const funding = fundingJson.data || {};
      const accountId = clean(funding.accountNo, 64);
      if (!accountId) {
        return Response.json({ error: "No USD PhotonPay account was found to fund the card. Open a USD account in the PhotonPay portal first." }, { status: 409 });
      }
      const available = Number(funding.realTimeBalance);
      if (cardType === "recharge" && Number.isFinite(available) && available < rechargeAmount) {
        return Response.json({ error: `The USD PhotonPay balance (${available.toFixed(2)}) is lower than the opening balance requested (${rechargeAmount.toFixed(2)}).` }, { status: 409 });
      }
      const body = {
        requestId: requestId("Z8"),
        ipAddress,
        gpsCountry,
        cardholderId: holder.cardholderId,
        cardCurrency: "USD",
        cardType,
        cardFormFactor: "virtual_card",
        accountId,
        rechargeAmount: cardType === "recharge" ? rechargeAmount : undefined,
        nickname: clean(input.nickname, 50) || undefined,
        maxOnDaily: numberOrUndefined(input.maxOnDaily),
        maxOnMonthly: numberOrUndefined(input.maxOnMonthly),
        maxOnPercent: numberOrUndefined(input.maxOnPercent),
        transactionLimitType: limited ? "limited" : "unlimited",
        transactionLimit: limited ? numberOrUndefined(input.transactionLimit) : undefined,
      };
      // Omit memberId and matrixAccount: PhotonPay uses the merchant owning
      // the configured App ID / App Secret, with this explicit cardholder.
      const json = await photonRequest(live, "/vcc/openApi/v4/openCardHalo", { method: "POST", body });
      const data = json.data || {};
      if (String(data.createCardStatus || "").toLowerCase() === "failed") {
        return Response.json({ error: `PhotonPay declined the card application (request ${body.requestId}).` }, { status: 409 });
      }
      // openCardHalo only acknowledges the application. The card is linked
      // later by the resolve action, the card-status webhook or the daily sync.
      return Response.json({
        request_id: body.requestId,
        status: "pending",
        photon_cardholder_id: data.cardholderId || holder.cardholderId,
        cardholder_record_id: refreshed.id,
        owner_email: ownerEmail,
        card: { currency: "USD" },
      });
    }

    if (action === "top_up_quote" || action === "top_up_confirm") {
      // Funding a Regular card from the USD PhotonPay account after the client
      // has paid: PhotonPay quotes first (preRecharge), then transfers in
      // (recharge) with the quote's requestId while it is valid.
      if (record.card_type !== "recharge") return Response.json({ error: "Only Regular cards hold their own balance." }, { status: 409 });
      if (record.status === "cancelled") return Response.json({ error: "A cancelled card cannot be topped up." }, { status: 409 });
      const whose = admin ? "The client's" : "Your";
      if (!admin) {
        // A client adds credit to their own active card, from their balance only.
        if (overRateLimit(user.id)) return Response.json({ error: "Too many requests. Please wait a minute and try again." }, { status: 429 });
        if (record.status !== "active") return Response.json({ error: record.status === "frozen" ? "Unfreeze the card before adding credit." : "Credit can be added once the card is active." }, { status: 409 });
        const settings = await programmeSettings(context);
        if (settings.client_topups_enabled === false) return Response.json({ error: "Adding credit is paused. Please contact support." }, { status: 409 });
      }
      if (action === "top_up_quote") {
        const amount = Math.round((Number(input.amount) || 0) * 100) / 100;
        if (!(amount > 0)) return Response.json({ error: admin ? "Enter the amount to load." : "Enter how much credit to add." }, { status: 400 });
        if (amount > 100000) return Response.json({ error: "Enter an amount up to 100,000 USD." }, { status: 400 });
        const funding = (await photonRequest(live, "/wallet/openApi/v4/account/single", { query: { currency: "USD", accountType: "FT10001" } })).data || {};
        const accountId = clean(funding.accountNo, 64);
        if (!accountId) return Response.json({ error: "No USD PhotonPay account to fund the card from." }, { status: 409 });
        if (Number.isFinite(Number(funding.realTimeBalance)) && Number(funding.realTimeBalance) < amount) {
          return Response.json({ error: `Your USD PhotonPay balance (${Number(funding.realTimeBalance).toFixed(2)}) is below ${amount.toFixed(2)}.` }, { status: 409 });
        }
        if (await isClientMoney(context, record.owner_email)) {
          const wallet = await walletOf(context, record.owner_email);
          if (amount > wallet.available) {
            return Response.json({
              error: admin
                ? `The client's available balance is ${wallet.available.toFixed(2)} USD, less than ${amount.toFixed(2)} USD. Record their deposit under Client funds first.`
                : `Your available balance is ${wallet.available.toFixed(2)} USD. Add funds to your account first, or add less credit.`,
              needs_funds: !admin,
            }, { status: 409 });
          }
        }
        const quoteId = requestId("Z8R");
        const quote = (await photonRequest(live, "/vcc/openApi/v4/preRecharge", { query: { requestId: quoteId, accountId, cardId: record.photon_card_id, rechargeAmount: amount } })).data || {};
        await context.entities.Card.update(record.id, { pending_topup_request_id: quoteId, pending_topup_amount: amount });
        return Response.json({
          request_id: quoteId, recharge_amount: quote.rechargeAmount ?? amount, arrival_amount: quote.arrivalAmount ?? null,
          fee: quote.rechargeFee ?? null, exchange_rate: quote.exchangeRate ?? null, valid_seconds: quote.effectiveQuotationTime ?? null,
          currency: quote.arrivalAmountCurrency || "USD",
        });
      }
      const quoteId = clean(input.requestId, 64);
      if (!quoteId || quoteId !== record.pending_topup_request_id) return Response.json({ error: "This quote is no longer valid. Get a new quote." }, { status: 409 });
      const clientMoney = await isClientMoney(context, record.owner_email);
      const quotedAmount = round2(record.pending_topup_amount);
      if (clientMoney) {
        const wallet = await walletOf(context, record.owner_email);
        if (!(quotedAmount > 0) || quotedAmount > wallet.available) {
          return Response.json({ error: `${whose} available balance is ${wallet.available.toFixed(2)} USD, not enough for this top-up. Get a new quote${admin ? " after recording their deposit" : ""}.` }, { status: 409 });
        }
      }
      const result = (await photonRequest(live, "/vcc/openApi/v4/recharge", { method: "POST", body: { requestId: quoteId } })).data || {};
      const balance = Number(result.cardBalance);
      await context.entities.Card.update(record.id, {
        pending_topup_request_id: "", pending_topup_amount: null,
        ...(Number.isFinite(balance) ? { balance } : {}),
      });
      const succeeded = ["succeed", "success", ""].includes(String(result.status || "").toLowerCase());
      if (succeeded && clientMoney) {
        // The client pays the fee: their account is charged what left the USD
        // account, and the card receives that less PhotonPay's fee.
        const charged = round2(Number(result.rechargeAmount) > 0 ? result.rechargeAmount : quotedAmount);
        await addEntry(context, {
          owner_email: String(record.owner_email).toLowerCase(), client_name: record.cardholder_name || "", kind: "card_topup", status: "completed",
          amount: -charged, card_id: record.id, note: `Top-up of ${record.nickname || "your card"}${record.last4 ? ` (…${record.last4})` : ""}`,
          reported_by: "admin", recorded_by: String(user.email || ""),
        });
        // A client sees their own top-up on screen; one made for them is announced.
        if (admin) {
          await notifyClient(context, record.owner_email, { kind: "card", tone: "success", title: "Credit added to your card", body: `${round2(result.arrivalAmount ?? charged).toFixed(2)} USD added to ${record.nickname || "your card"}${record.last4 ? ` (•••• ${record.last4})` : ""}.`, link: `/cards/${record.id}`, key: `topup:${quoteId}` });
        }
      }
      const wasLocked = Boolean(record.auto_issued && !record.funded_at);
      const txn = {
        transactionId: result.transactionId, requestId: quoteId, transactionType: "recharge", status: result.status || "succeed",
        transactionAmount: result.arrivalAmount ?? result.rechargeAmount, transactionCurrency: result.arrivalAmountCurrency || "USD",
        createdAt: result.createdAt || new Date().toISOString(),
      };
      // Recorded under PhotonPay's transactionId so the webhook and daily sync
      // recognise it instead of adding it twice; that also unlocks the card.
      if (result.transactionId) await saveTransaction(context, record, txn);
      if (succeeded) await unlockIfFunded(context, record, txn);
      return Response.json({ ok: true, status: result.status || "", balance: Number.isFinite(balance) ? balance : null, arrival_amount: result.arrivalAmount ?? null, fee: result.rechargeFee ?? null, unlocked: wasLocked && succeeded });
    }

    if (action === "unblock_cvv") {
      // After too many wrong CVV entries PhotonPay blocks the CVV; this lifts it.
      // Idempotent at PhotonPay: an unblocked CVV also returns success.
      await photonRequest(live, "/vcc/openApi/v4/unblockCvv", { method: "POST", body: { cardId: record.photon_card_id } });
      await context.entities.CardTransaction.create({
        kind: "event", event: "CVV unblocked", card_id: record.id, card_last4: record.last4,
        card_nickname: record.nickname, amount: 0, currency: record.currency, status: "completed",
        occurred_at: new Date().toISOString(), owner_email: record.owner_email || "", note: "CVV unblocked",
      });
      return Response.json({ ok: true });
    }

    if (action === "update_card") {
      // PhotonPay updateCard changes the nickname and the card's overall
      // transaction limit; daily, monthly and per-payment caps are fixed at issue.
      const body = { cardId: record.photon_card_id, requestId: requestId("Z8"), cardFormFactor: "virtual_card" };
      const nickname = clean(input.nickname, 51);
      if (input.nickname !== undefined) {
        if (!nickname || nickname.length > 50) return Response.json({ error: "The card name must be 1 to 50 characters." }, { status: 400 });
        body.nickname = nickname;
      }
      const limitType = clean(input.transactionLimitType, 20);
      if (limitType) {
        if (!["limited", "unlimited"].includes(limitType)) return Response.json({ error: "Choose limited or unlimited spending." }, { status: 400 });
        body.transactionLimitType = limitType;
        if (limitType === "limited") {
          const amount = Math.round((Number(input.transactionLimit) || 0) * 100) / 100;
          const change = clean(input.transactionLimitChangeType, 10);
          if (!(amount > 0)) return Response.json({ error: "Enter the amount to change the spending limit by." }, { status: 400 });
          if (!["increase", "decrease"].includes(change)) return Response.json({ error: "Choose whether to increase or decrease the limit." }, { status: 400 });
          if (record.status === "cancelled" && change === "increase") return Response.json({ error: "A cancelled card's limit can only be decreased." }, { status: 409 });
          body.transactionLimit = amount;
          body.transactionLimitChangeType = change;
        }
      }
      if (!body.nickname && !body.transactionLimitType) return Response.json({ error: "Nothing to change." }, { status: 400 });
      const json = await photonRequest(live, "/vcc/openApi/v4/updateCard", { method: "POST", body });
      const data = json.data || {};
      const update = {
        ...(body.nickname ? { nickname: body.nickname } : {}),
        ...(body.transactionLimitType ? { transaction_limit_type: body.transactionLimitType } : {}),
      };
      if (Object.keys(update).length) await context.entities.Card.update(record.id, update);
      const what = [body.nickname ? `renamed to "${body.nickname}"` : "",
        body.transactionLimitType === "unlimited" ? "spending limit removed" : "",
        body.transactionLimitChangeType ? `spending limit ${body.transactionLimitChangeType}d by ${body.transactionLimit} ${record.currency || "USD"}` : ""].filter(Boolean).join(", ");
      await context.entities.CardTransaction.create({
        kind: "event", event: "Card updated", card_id: record.id, card_last4: record.last4,
        card_nickname: body.nickname || record.nickname, amount: 0, currency: record.currency, status: "completed",
        occurred_at: new Date().toISOString(), owner_email: record.owner_email || "", note: what,
      });
      return Response.json({
        ok: true, nickname: body.nickname || record.nickname,
        transaction_limit_type: data.transactionLimitType || body.transactionLimitType || record.transaction_limit_type,
        available_transaction_limit: data.availableTransactionLimit ?? null,
      });
    }

    if (action === "sandbox_txn") {
      // PhotonPay sandbox only: simulate a card payment, void or refund so the
      // webhooks, the daily sync and the decline alerts can be tested.
      if (live.env !== "sandbox") return Response.json({ error: "Test transactions are only available in the PhotonPay sandbox." }, { status: 409 });
      const txnType = clean(input.txnType, 10);
      if (!["auth", "void", "refund"].includes(txnType)) return Response.json({ error: "Choose auth, void or refund." }, { status: 400 });
      const amount = Math.round((Number(input.amount) || 0) * 100) / 100;
      if (!(amount > 0)) return Response.json({ error: "Enter an amount." }, { status: 400 });
      const originTransactionId = clean(input.originTransactionId, 80);
      if (txnType !== "auth" && !originTransactionId) return Response.json({ error: "A void or refund needs the original transaction ID." }, { status: 400 });
      const mcc = clean(input.mcc, 4) || "5999";
      if (!/^\d{4}$/.test(mcc)) return Response.json({ error: "The merchant category code (MCC) is 4 digits." }, { status: 400 });
      // The sandbox needs the card's CVV and expiry; they are read here, used
      // for this one call and never returned, stored or logged.
      const detail = (await photonRequest(live, "/vcc/openApi/v4/getCardDetail", { query: { cardId: record.photon_card_id } })).data || {};
      const cvv = (await photonRequest(live, "/vcc/openApi/v4/getCvv", { query: { cardId: record.photon_card_id } })).data?.cvv || "";
      const expiry = String(detail.expirationDate || detail.expiryDate || "");
      if (!cvv || !/^\d{2}\/\d{2}$/.test(expiry)) return Response.json({ error: "PhotonPay did not return this card's CVV and expiry." }, { status: 502 });
      const body = {
        requestId: requestId("Z8T"), cardID: record.photon_card_id, cvv, expirationDate: expiry,
        originTransactionId: txnType === "auth" ? "" : originTransactionId,
        txnCurrency: record.currency || "USD", txnAmount: amount, txnType, mcc,
        merchantName: clean(input.merchantName, 40) || "Z8 sandbox test",
        merchantCountry: "US", merchantCity: "Newyork", merchantPostcode: "10001",
      };
      await photonRequest(live, "/vcc/open/v2/sandBoxTransaction", { method: "POST", body });
      return Response.json({ ok: true, request_id: body.requestId, note: "PhotonPay will send the transaction by webhook; it appears in the card's activity shortly." });
    }

    if (action === "edit_holder") {
      // Correct a cardholder at PhotonPay (e.g. after a "modify" or "rejected"
      // review). Only the fields provided are sent; each is checked by the same
      // rules as registration.
      const holder = await context.entities.Cardholder.get(clean(input.cardholderRecordId, 64)).catch(() => null);
      if (!holder?.photon_cardholder_id) return Response.json({ error: "This client is not linked to PhotonPay." }, { status: 404 });
      const keys = ["firstName", "lastName", "dateOfBirth", "nationalityCountryCode", "email", "mobile", "mobilePrefix",
        "residentialAddress", "residentialCity", "residentialState", "residentialPostalCode", "residentialCountryCode",
        "certType", "certId", "certCountryCode"];
      const provided = keys.filter((key) => input[key] !== undefined && String(input[key]).trim() !== "");
      if (!provided.length) return Response.json({ error: "Nothing to change." }, { status: 400 });
      // Validate the provided fields against a complete, valid placeholder so
      // only problems in what the administrator entered are reported.
      const placeholder = { firstName: "A", lastName: "B", dateOfBirth: "1990-01-01", nationalityCountryCode: "AE", email: "a@b.co",
        residentialAddress: "x", residentialCity: "x", residentialState: "x", residentialPostalCode: "x", residentialCountryCode: "AE",
        certType: "passport", certId: "x", certCountryCode: "AE" };
      const merged = { ...placeholder };
      for (const key of provided) merged[key] = input[key];
      if (provided.includes("mobile") && !provided.includes("mobilePrefix")) return Response.json({ error: "Enter the country calling code with the mobile number." }, { status: 400 });
      const { problems, fields } = validateHolder(merged);
      if (problems.length) return Response.json({ error: problems.join(". ") + ".", problems }, { status: 400 });
      const body = { cardholderId: holder.photon_cardholder_id };
      for (const key of provided) body[key] = fields[key];
      await photonRequest(live, "/vcc/openApi/v4/editCardholder", { method: "POST", body });
      const local = {
        ...(body.firstName ? { first_name: body.firstName } : {}), ...(body.lastName ? { last_name: body.lastName } : {}),
        ...(body.dateOfBirth ? { date_of_birth: body.dateOfBirth } : {}), ...(body.nationalityCountryCode ? { nationality: body.nationalityCountryCode } : {}),
        ...(body.email ? { email: body.email } : {}), ...(body.mobile ? { phone: `${body.mobilePrefix} ${body.mobile}` } : {}),
        ...(body.residentialAddress ? { address_line: body.residentialAddress } : {}), ...(body.residentialCity ? { city: body.residentialCity } : {}),
        ...(body.residentialState ? { state: body.residentialState } : {}), ...(body.residentialPostalCode ? { postal_code: body.residentialPostalCode } : {}),
        ...(body.residentialCountryCode ? { country: body.residentialCountryCode } : {}), ...(body.certType ? { cert_type: body.certType } : {}),
        ...(body.certId ? { cert_id: maskIdNumber(body.certId) } : {}), ...(body.certCountryCode ? { cert_country: body.certCountryCode } : {}),
      };
      if (body.firstName || body.lastName) local.full_name = `${body.firstName || holder.first_name || ""} ${body.lastName || holder.last_name || ""}`.trim();
      await context.entities.Cardholder.update(holder.id, local);
      // Read back PhotonPay's review status after the change.
      const remote = await photonRequest(live, "/vcc/openApi/v4/pagingVccCardholder", { query: { cardholderId: holder.photon_cardholder_id, pageIndex: 1, pageSize: 10 } }).catch(() => null);
      const row = remote ? rowsOf(remote).find((item) => item.cardholderId === holder.photon_cardholder_id) : null;
      const refreshed = row ? await saveHolder(context, row, live, { ...holder, ...local }) : { ...holder, ...local };
      return Response.json({ ok: true, status: refreshed.status, provider_status: refreshed.provider_status, review_status: refreshed.review_status, changed: provided });
    }

    if (action === "freeze" || action === "unfreeze" || action === "cancel") {
      const cardId = record.photon_card_id;
      if (!cardId) return Response.json({ error: "cardId is required" }, { status: 400 });
      // Freeze and unfreeze share one endpoint with a status field; discard takes only cardId.
      if (action === "cancel") {
        await photonRequest(live, "/vcc/openApi/v4/cancelCard", { method: "POST", body: { cardId } });
      } else {
        await photonRequest(live, "/vcc/openApi/v4/freezeCard", {
          method: "POST",
          body: { cardId, requestId: requestId("Z8"), status: action },
        });
      }
      const nextStatus = action === "freeze" ? "frozen" : action === "unfreeze" ? "active" : "cancelled";
      const event = action === "freeze" ? "Card frozen" : action === "unfreeze" ? "Card unfrozen" : "Card cancelled";
      await context.entities.Card.update(record.id, { status: nextStatus });
      await context.entities.CardTransaction.create({
        kind: "event", event, card_id: record.id, card_last4: record.last4,
        card_nickname: record.nickname, amount: 0, currency: record.currency,
        status: "completed", occurred_at: new Date().toISOString(),
        owner_email: record.owner_email || "",
        note: event,
      });
      if (admin && record.owner_email && record.owner_email.toLowerCase() !== String(user.email || "").toLowerCase()) {
        await notifyClient(context, record.owner_email, {
          kind: "card", tone: action === "unfreeze" ? "info" : "warning",
          title: action === "freeze" ? "Your card was frozen" : action === "unfreeze" ? "Your card is active again" : "Your card was cancelled",
          body: `${record.nickname || "Your card"}${record.last4 ? ` (•••• ${record.last4})` : ""}${action === "freeze" ? " can't be used for now. Contact support if you didn't expect this." : action === "unfreeze" ? " can be used again." : " has been cancelled and can no longer be used."}`,
          link: `/cards/${record.id}`, key: `${action}:${record.id}:${Date.now()}`,
        });
      }
      return Response.json({ ok: true, status: nextStatus });
    }

    return Response.json({ error: "Unsupported action" }, { status: 400 });
  } catch (error) {
    console.log("photonpayCards error:", error.message);
    // Administrators need the provider's own reason to fix the connection;
    // customers must never see provider diagnostics or configuration details.
    // The provider's reason code is already appended where it applies; repeat it
    // only when it is missing, so administrators read one clean sentence.
    const codeNote = error.providerCode && !String(error.message || "").includes(error.providerCode) ? `code ${error.providerCode}` : "";
    const stageNote = error.stage && error.stage !== "provider" ? `stage ${error.stage}` : "";
    const detail = [error.message, codeNote, stageNote].filter(Boolean).join(" · ");
    return Response.json({
      error: admin && detail ? detail : "We couldn't complete this card request. Please try again or contact your administrator.",
    }, { status: 500 });
  }
}

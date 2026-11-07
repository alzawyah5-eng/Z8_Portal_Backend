// @ts-nocheck
import { notifyAdmins } from "./photonpay";

export default async function (req, context) {
  try {
    if (req.method !== "POST") return Response.json({ error: "Method not allowed" }, { status: 405, headers: { Allow: "POST" } });

    const user = await context.auth.me().catch((e) => (e.status === 401 ? null : Promise.reject(e)));
    if (!user) return Response.json({ error: "Unauthorized" }, { status: 401 });
    // Only a real card-programme account may erase itself; a session without an
    // app role is refused, exactly as the card function does.
    if (user.role !== "admin" && user.role !== "user") {
      return Response.json({ error: "Account access is unavailable" }, { status: 403 });
    }

    // Deleting is irreversible, so the caller has to echo the signed-in
    // account's own email back. A blind or replayed request cannot erase an
    // account, and the address deleted is always the session's, never the body's.
    const body = await req.json().catch(() => ({}));
    const confirmation = String(body.confirm_email || "").trim().toLowerCase();
    if (!confirmation || confirmation !== String(user.email || "").trim().toLowerCase()) {
      return Response.json({ error: "Confirm the account email to continue" }, { status: 400 });
    }

    const closedAccount = await context.accounts.close(user.id);
    if (user.role === "user") {
      await notifyAdmins(context, {
        kind: "account", tone: "warning", title: "A client closed their account",
        body: `The client account ${user.email} was closed.`,
        link: "/cardholders", key: `admin-account-deleted:${closedAccount.id}`,
      }).catch(() => undefined);
    }

    return Response.json({ ok: true });
  } catch (error) {
    const response = typeof error?.getResponse === "function" ? error.getResponse() : null;
    const message = typeof response === "string"
      ? response
      : response?.message || error.message || "Account closure could not be completed.";
    return Response.json({
      error: Array.isArray(message) ? message.join(", ") : String(message),
      ...(response?.code ? { code: response.code } : {}),
    }, { status: Number(error?.status) || 500 });
  }
}

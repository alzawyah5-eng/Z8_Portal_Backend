// @ts-nocheck

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

    // Release every card and piece of activity assigned to this account before
    // the account itself is removed, so nothing is left pointing at a gone user.
    const query = { owner_email: user.email };
    await context.entities.Card.updateMany(query, { $set: { owner_email: "" } });
    await context.entities.CardTransaction.updateMany(query, { $set: { owner_email: "" } });
    await context.entities.User.delete(user.id);

    return Response.json({ ok: true });
  } catch (error) {
    return Response.json({ error: error.message }, { status: 500 });
  }
}
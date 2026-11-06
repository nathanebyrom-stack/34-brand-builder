// 34 Brand Builder: personal client links.
// One endpoint, POST JSON {action, ...}. Client actions use the link token; admin actions need x-admin-key.
// Tables are RLS-locked; only this function (service role) reads or writes them.
import { createClient } from "npm:@supabase/supabase-js@2.45.4";

const SITE_URL = "https://clients.34automation.co.uk/client/";
const MAX_BODY = 4_000_000; // worksheet can carry mood-board images

const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
  auth: { persistSession: false },
});

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "content-type, x-admin-key, apikey, authorization",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...CORS, "Content-Type": "application/json" } });
const fail = (code: string, status = 400) => json({ ok: false, code }, status);

async function sha256(s: string) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function newToken() {
  const b = crypto.getRandomValues(new Uint8Array(24));
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function sameText(a: string, b: string) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
const clean = (v: unknown, max = 200) => (typeof v === "string" ? v.trim().slice(0, max) : "");

// ---------- client side ----------
async function loadLink(token: unknown, device: unknown) {
  if (typeof token !== "string" || token.length < 20 || token.length > 64) return { err: "invalid" };
  if (typeof device !== "string" || device.length < 16 || device.length > 64) return { err: "no_device" };
  const { data: link } = await db.from("links").select("*").eq("token_hash", await sha256(token)).maybeSingle();
  if (!link) return { err: "invalid" };
  if (link.revoked) return { err: "revoked" };
  if (link.submitted_at) return { err: "submitted", link };
  if (new Date(link.expires_at) < new Date()) return { err: "expired" };
  if (link.device_id && link.device_id !== device) {
    await db.from("links").update({ blocked_attempts: link.blocked_attempts + 1 }).eq("id", link.id);
    return { err: "other_device" };
  }
  return { link };
}

async function clientAction(action: string, body: Record<string, unknown>) {
  const { link, err } = await loadLink(body.token, body.device);
  if (err) {
    if (err === "submitted") return json({ ok: false, code: err, client_name: link.client_name });
    return fail(err, err === "invalid" ? 404 : 403);
  }
  const now = new Date().toISOString();
  if (action === "open") {
    const patch: Record<string, unknown> = { last_seen_at: now, open_count: link.open_count + 1 };
    if (!link.device_id) { patch.device_id = body.device; patch.first_opened_at = now; }
    await db.from("links").update(patch).eq("id", link.id);
    return json({
      ok: true, client_name: link.client_name, company: link.company, client_email: link.client_email,
      worksheet: link.worksheet, expires_at: link.expires_at,
    });
  }
  if (action === "save" || action === "submit") {
    if (!body.worksheet || typeof body.worksheet !== "object") return fail("no_worksheet");
    const patch: Record<string, unknown> = { worksheet: body.worksheet, saved_at: now, last_seen_at: now };
    if (action === "submit") patch.submitted_at = now;
    const { error } = await db.from("links").update(patch).eq("id", link.id);
    if (error) return fail("save_failed", 500);
    return json({ ok: true, saved_at: now, submitted: action === "submit" });
  }
  return fail("unknown_action");
}

// ---------- admin side ----------
async function isAdmin(req: Request) {
  const key = req.headers.get("x-admin-key") || "";
  if (key.length < 8 || key.length > 100) return false;
  const { data } = await db.from("settings").select("value").eq("key", "admin_key_hash").maybeSingle();
  return !!data && sameText(await sha256(key), data.value);
}
const LIST_COLS =
  "id, client_name, client_email, company, note, created_at, expires_at, revoked, device_id, first_opened_at, last_seen_at, open_count, blocked_attempts, saved_at, submitted_at";

async function adminAction(action: string, body: Record<string, unknown>) {
  const id = clean(body.id, 40);
  const days = Math.min(Math.max(Number(body.days) || 30, 1), 365);
  const until = new Date(Date.now() + days * 864e5).toISOString();
  switch (action) {
    case "check": return json({ ok: true });
    case "create": {
      const client_name = clean(body.client_name, 120);
      if (!client_name) return fail("name_required");
      const token = newToken();
      const { data, error } = await db.from("links").insert({
        token_hash: await sha256(token), client_name, client_email: clean(body.client_email, 200) || null,
        company: clean(body.company, 160) || null, note: clean(body.note, 500) || null, expires_at: until,
      }).select(LIST_COLS).single();
      if (error) return fail("create_failed", 500);
      return json({ ok: true, link: data, url: SITE_URL + "?k=" + token });
    }
    case "list": {
      const { data, error } = await db.from("links").select(LIST_COLS).order("created_at", { ascending: false }).limit(500);
      if (error) return fail("list_failed", 500);
      return json({ ok: true, links: data });
    }
    case "get": {
      const { data } = await db.from("links").select("*").eq("id", id).maybeSingle();
      if (!data) return fail("not_found", 404);
      delete data.token_hash;
      return json({ ok: true, link: data });
    }
    case "reissue": { // new link, old one stops working; keeps their answers
      const token = newToken();
      const { error } = await db.from("links").update({ token_hash: await sha256(token), device_id: null, revoked: false, expires_at: until }).eq("id", id);
      if (error) return fail("update_failed", 500);
      return json({ ok: true, url: SITE_URL + "?k=" + token });
    }
    case "reset_device":
    case "revoke":
    case "restore":
    case "extend":
    case "reopen": {
      const patch = action === "reset_device" ? { device_id: null }
        : action === "revoke" ? { revoked: true }
        : action === "restore" ? { revoked: false }
        : action === "extend" ? { expires_at: until }
        : { submitted_at: null, alerted_at: null };
      const { error } = await db.from("links").update(patch).eq("id", id);
      if (error) return fail("update_failed", 500);
      return json({ ok: true });
    }
    case "delete": {
      if (body.confirm !== "delete") return fail("confirm_required");
      const { error } = await db.from("links").delete().eq("id", id);
      if (error) return fail("delete_failed", 500);
      return json({ ok: true });
    }
  }
  return fail("unknown_action");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: CORS });
  if (req.method !== "POST") return fail("method", 405);
  const len = Number(req.headers.get("content-length") || 0);
  if (len > MAX_BODY) return fail("too_large", 413);
  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return fail("bad_json"); }
  const action = clean(body.action, 30);
  try {
    if (action === "ping") {
      await db.from("pings").insert({});
      await db.from("pings").delete().lt("at", new Date(Date.now() - 90 * 864e5).toISOString());
      return json({ ok: true });
    }
    if (["open", "save", "submit"].includes(action)) return await clientAction(action, body);
    if (!(await isAdmin(req))) return fail("not_admin", 401);
    return await adminAction(action, body);
  } catch (_e) {
    return fail("server_error", 500);
  }
});

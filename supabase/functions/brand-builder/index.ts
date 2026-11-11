// 34 Brand Builder: personal client links.
// One endpoint, POST JSON {action, ...}. Client actions use the link token; admin actions need x-admin-key.
// Sign-in (added Nov 2026): a client can also get in with a username + password set by Nathan in admin.
// sign_in swaps those for a short-lived session token that the Brand Builder uses in place of the link.
// Tables are RLS-locked; only this function (service role) reads or writes them.
// Passwords are never stored or logged: only a salted PBKDF2-SHA-256 hash.
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

// ---------- sign-in helpers ----------
const SESSION_HOURS = 12;
const PW_ITER = 600_000; // PBKDF2-SHA-256 iterations for new hashes (stored per user, so it can be raised later)
const SIGNIN_ORIGINS = new Set(["https://34automation.co.uk", "https://www.34automation.co.uk"]);
const LOCAL_ORIGIN = /^http:\/\/(localhost|127\.0\.0\.1)(:\d{1,5})?$/;
const USER_RE = /^[a-z0-9][a-z0-9._@-]{2,63}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SESSION_RE = /^[A-Za-z0-9_-]{40,64}$/;
const enc = new TextEncoder();
const hex = (buf: ArrayBuffer) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const b64 = (u8: Uint8Array) => btoa(String.fromCharCode(...u8));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const normUser = (v: unknown) => (typeof v === "string" ? v.normalize("NFKC").trim().toLowerCase().slice(0, 64) : "");
const normPass = (v: unknown) => (typeof v === "string" ? v.normalize("NFC") : "");
const signInOriginOk = (o: string) => SIGNIN_ORIGINS.has(o) || LOCAL_ORIGIN.test(o);
const DUMMY_SALT = crypto.getRandomValues(new Uint8Array(16)); // unknown usernames still pay for one hash

function randomToken(bytes: number) {
  const b = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function pbkdf2(password: string, salt: Uint8Array<ArrayBuffer>, iterations: number) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256));
}
function sameBytes(a: Uint8Array, b: Uint8Array) { // constant time for equal lengths
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a[i] ^ b[i];
  return r === 0;
}
// Failed-attempt counters are keyed by a keyed hash, so no usernames or IP addresses are stored.
let attemptHmac: Promise<CryptoKey> | null = null;
async function attemptKey(prefix: "u:" | "ip:", value: string) {
  attemptHmac ??= crypto.subtle.importKey(
    "raw", enc.encode("bb34-attempts|" + (Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "")),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  return prefix + hex(await crypto.subtle.sign("HMAC", await attemptHmac, enc.encode(prefix + value))).slice(0, 40);
}
function clientIp(req: Request) {
  const xff = (req.headers.get("x-forwarded-for") || "").split(",")[0].trim();
  return (req.headers.get("cf-connecting-ip") || xff || req.headers.get("x-real-ip") || "unknown").slice(0, 64);
}

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

// ---------- sign-in (username + password) ----------
// Only answers browsers on 34automation.co.uk (and localhost for testing); every answer is no-store.
async function signIn(req: Request, body: Record<string, unknown>) {
  const origin = req.headers.get("origin") || "";
  if (!signInOriginOk(origin)) {
    return new Response(JSON.stringify({ ok: false, code: "origin" }), { status: 403, headers: { "Content-Type": "application/json", Vary: "Origin" } });
  }
  const out = (b: unknown, status = 200) => new Response(JSON.stringify(b), {
    status,
    headers: {
      "Access-Control-Allow-Origin": origin, Vary: "Origin", "Cache-Control": "no-store",
      "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "content-type",
      "Content-Type": "application/json",
    },
  });
  const lockedOut = (until: string) =>
    out({ ok: false, code: "locked", retry_after: Math.max(1, Math.ceil((new Date(until).getTime() - Date.now()) / 1000)) }, 429);

  // housekeeping on every attempt: counters older than a day, sessions a week past expiry
  await db.from("login_attempts").delete().lt("updated_at", new Date(Date.now() - 864e5).toISOString());
  await db.from("sessions").delete().lt("expires_at", new Date(Date.now() - 7 * 864e5).toISOString());

  const username = normUser(body.username);
  const password = normPass(body.password);
  if (!username || !password) return out({ ok: false, code: "missing" }, 400);

  const keys = [await attemptKey("u:", username), await attemptKey("ip:", clientIp(req))];
  const nowIso = new Date().toISOString();
  const { data: locks, error: lockErr } = await db.from("login_attempts").select("locked_until").in("key", keys).gt("locked_until", nowIso);
  if (lockErr) return out({ ok: false, code: "server_error" }, 500);
  if (locks && locks.length) return lockedOut(locks.map((l) => l.locked_until).sort().at(-1)!);

  const { data: login } = await db.from("logins").select("link_id, pw_iter, pw_salt, pw_hash, login_count").eq("username", username).maybeSingle();
  const tooLong = password.length > 200;
  const iter = login ? Math.min(Math.max(Number(login.pw_iter) || PW_ITER, 210_000), 2_000_000) : PW_ITER;
  const got = await pbkdf2(tooLong ? "-" : password, login ? unb64(login.pw_salt) : DUMMY_SALT, iter);
  const good = !!login && !tooLong && sameBytes(got, unb64(login.pw_hash));
  if (!good) {
    const { data: until, error } = await db.rpc("bb_login_fail", { p_keys: keys });
    if (error) return out({ ok: false, code: "server_error" }, 500);
    if (until) return lockedOut(until as string);
    return out({ ok: false, code: "bad_login" }, 401); // same answer whether or not the username exists
  }

  await db.from("login_attempts").delete().eq("key", keys[0]); // right password clears the username counter
  const { data: link } = await db.from("links").select("id, client_name, revoked, expires_at").eq("id", login.link_id).maybeSingle();
  if (!link) return out({ ok: false, code: "bad_login" }, 401);
  if (link.revoked) return out({ ok: false, code: "revoked" }, 403);
  if (new Date(link.expires_at) < new Date()) return out({ ok: false, code: "expired" }, 403);

  const session = randomToken(32);
  const expires_at = new Date(Date.now() + SESSION_HOURS * 36e5).toISOString();
  const { error: sErr } = await db.from("sessions").insert({ token_hash: await sha256(session), link_id: link.id, expires_at });
  if (sErr) return out({ ok: false, code: "server_error" }, 500);
  await db.from("logins").update({ last_login_at: nowIso, login_count: (login.login_count || 0) + 1 }).eq("link_id", link.id);
  return out({ ok: true, session, expires_at, url: SITE_URL + "#s=" + session, client_name: link.client_name });
}

// Session versions of open / save / submit. A session proves the password, so opening with it
// moves the one-device lock to this device; the session itself then sticks to this device.
async function loadSession(session: unknown, device: unknown) {
  if (typeof session !== "string" || !SESSION_RE.test(session)) return { err: "session_invalid" };
  if (typeof device !== "string" || device.length < 16 || device.length > 64) return { err: "no_device" };
  const { data: s } = await db.from("sessions").select("id, link_id, expires_at, revoked, device_id").eq("token_hash", await sha256(session)).maybeSingle();
  if (!s || s.revoked) return { err: "session_invalid" };
  if (new Date(s.expires_at) < new Date()) return { err: "session_expired" };
  if (s.device_id && s.device_id !== device) return { err: "other_device" };
  const { data: link } = await db.from("links").select("*").eq("id", s.link_id).maybeSingle();
  if (!link) return { err: "session_invalid" };
  if (link.revoked) return { err: "revoked" };
  if (link.submitted_at) return { err: "submitted", link };
  if (new Date(link.expires_at) < new Date()) return { err: "expired" };
  return { s, link };
}

async function sessionAction(action: string, body: Record<string, unknown>) {
  const r = await loadSession(body.session, body.device);
  if (r.err) {
    if (r.err === "submitted") return json({ ok: false, code: r.err, client_name: r.link.client_name });
    return fail(r.err, r.err === "session_invalid" || r.err === "session_expired" ? 401 : 403);
  }
  const s = r.s!, link = r.link;
  const device = body.device as string;
  const now = new Date().toISOString();
  if (action === "session_open") {
    if (!s.device_id) {
      const { data: bound } = await db.from("sessions").update({ device_id: device, last_seen_at: now }).eq("id", s.id).is("device_id", null).select("device_id");
      if (!bound || !bound.length) {
        const { data: again } = await db.from("sessions").select("device_id").eq("id", s.id).maybeSingle();
        if (!again || again.device_id !== device) return fail("other_device", 403);
      }
    } else {
      await db.from("sessions").update({ last_seen_at: now }).eq("id", s.id);
    }
    const patch: Record<string, unknown> = { last_seen_at: now, open_count: link.open_count + 1, device_id: device };
    if (!link.first_opened_at) patch.first_opened_at = now;
    await db.from("links").update(patch).eq("id", link.id);
    return json({
      ok: true, client_name: link.client_name, company: link.company, client_email: link.client_email,
      worksheet: link.worksheet, expires_at: link.expires_at, session_expires_at: s.expires_at,
      ref: (await sha256("ref|" + link.id)).slice(0, 16),
    });
  }
  if (action === "session_save" || action === "session_submit") {
    if (link.device_id && link.device_id !== device) return fail("other_device", 403);
    if (!body.worksheet || typeof body.worksheet !== "object") return fail("no_worksheet");
    const patch: Record<string, unknown> = { worksheet: body.worksheet, saved_at: now, last_seen_at: now };
    if (action === "session_submit") patch.submitted_at = now;
    const { error } = await db.from("links").update(patch).eq("id", link.id);
    if (error) return fail("save_failed", 500);
    await db.from("sessions").update({ last_seen_at: now }).eq("id", s.id);
    return json({ ok: true, saved_at: now, submitted: action === "session_submit" });
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
    // ----- sign-in management (added Nov 2026) -----
    case "set_login": { // set or reset a client's username + password; signs out their open sessions
      if (!UUID_RE.test(id)) return fail("not_found", 404);
      const username = normUser(body.username);
      const password = normPass(body.password);
      if (!USER_RE.test(username)) return fail("bad_username");
      if (password.length < 10 || password.length > 200) return fail("bad_password");
      const { data: link } = await db.from("links").select("id").eq("id", id).maybeSingle();
      if (!link) return fail("not_found", 404);
      const { data: taken } = await db.from("logins").select("link_id").eq("username", username).maybeSingle();
      if (taken && taken.link_id !== id) return fail("username_taken", 409);
      const { data: prev } = await db.from("logins").select("username").eq("link_id", id).maybeSingle();
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const hash = await pbkdf2(password, salt, PW_ITER);
      const { error } = await db.from("logins").upsert({
        link_id: id, username, pw_algo: "pbkdf2-sha256", pw_iter: PW_ITER, pw_salt: b64(salt), pw_hash: b64(hash),
        set_at: new Date().toISOString(),
      }, { onConflict: "link_id" });
      if (error) return error.code === "23505" ? fail("username_taken", 409) : fail("update_failed", 500);
      await db.from("sessions").update({ revoked: true }).eq("link_id", id).eq("revoked", false);
      const clear = [await attemptKey("u:", username)];
      if (prev && prev.username !== username) clear.push(await attemptKey("u:", prev.username));
      await db.from("login_attempts").delete().in("key", clear);
      return json({ ok: true, username });
    }
    case "clear_login": { // remove the sign-in; their personal link is unaffected
      if (!UUID_RE.test(id)) return fail("not_found", 404);
      const { error } = await db.from("logins").delete().eq("link_id", id);
      if (error) return fail("update_failed", 500);
      await db.from("sessions").update({ revoked: true }).eq("link_id", id).eq("revoked", false);
      return json({ ok: true });
    }
    case "logins": { // who has a sign-in, when it was last used, and any lock in force
      const { data, error } = await db.from("logins").select("link_id, username, set_at, last_login_at, login_count").limit(1000);
      if (error) return fail("list_failed", 500);
      const keys = await Promise.all(data.map((l) => attemptKey("u:", l.username)));
      const locked = new Map<string, string>();
      if (keys.length) {
        const { data: locks } = await db.from("login_attempts").select("key, locked_until").in("key", keys).gt("locked_until", new Date().toISOString());
        (locks || []).forEach((l) => locked.set(l.key, l.locked_until));
      }
      return json({ ok: true, logins: data.map((l, i) => ({ ...l, locked_until: locked.get(keys[i]) || null })) });
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
    if (action === "sign_in") return await signIn(req, body);
    if (["open", "save", "submit"].includes(action)) return await clientAction(action, body);
    if (["session_open", "session_save", "session_submit"].includes(action)) return await sessionAction(action, body);
    if (!(await isAdmin(req))) return fail("not_admin", 401);
    return await adminAction(action, body);
  } catch (_e) {
    return fail("server_error", 500);
  }
});

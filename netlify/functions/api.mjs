import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const BASE = "https://api.smtp.dev";
const LIFETIME_MS = 10 * 60 * 1000;
const MAX_AHEAD_MS = 60 * 60 * 1000;

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function apiKey() {
  const key = process.env.SMTPDEV_API_KEY;
  if (!key) throw new HttpError(500, "Mail service is not configured");
  return key;
}

// Use SIGNING_SECRET if provided, otherwise derive a stable signing key from the API key.
function signingKey() {
  return process.env.SIGNING_SECRET || createHmac("sha256", apiKey()).update("wisp-token-signing").digest("hex");
}

const b64 = (s) => Buffer.from(s).toString("base64url");

function sign(payload) {
  const body = b64(JSON.stringify(payload));
  const sig = createHmac("sha256", signingKey()).update(body).digest("base64url");
  return `${body}.${sig}`;
}

function verify(token) {
  if (typeof token !== "string" || !token.includes(".")) throw new HttpError(401, "Invalid token");
  const [body, sig] = token.split(".");
  const expected = createHmac("sha256", signingKey()).update(body).digest("base64url");
  const a = Buffer.from(sig || "");
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) throw new HttpError(401, "Invalid token");
  try {
    return JSON.parse(Buffer.from(body, "base64url").toString());
  } catch {
    throw new HttpError(401, "Invalid token");
  }
}

async function smtp(path, { method = "GET", body } = {}) {
  const res = await fetch(BASE + path, {
    method,
    headers: {
      "X-API-KEY": apiKey(),
      Accept: "application/json",
      ...(body ? { "Content-Type": method === "PATCH" ? "application/merge-patch+json" : "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const status = res.status === 404 ? 410 : res.status === 429 ? 429 : 502;
    throw new HttpError(status, (data && (data.detail || data.message)) || "Mail service error");
  }
  return data;
}

const members = (d) => (d && (d.member || d["hydra:member"])) || [];

const fmtFrom = (f) => (f ? (f.name ? `${f.name} <${f.address}>` : f.address) : "Unknown sender");

function htmlToText(html) {
  return String(html || "")
    .replace(/<(style|script)[\s\S]*?<\/\1>/gi, "")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(p|div|tr|h\d|li)>/gi, "\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

async function destroyAccount(acc) {
  try {
    await smtp(`/accounts/${encodeURIComponent(acc)}`, { method: "DELETE" });
  } catch {}
}

// Validates the session token; deletes the account and returns 410 once it has expired.
async function session(input) {
  const t = verify(input.token);
  if (Date.now() > t.exp) {
    await destroyAccount(t.acc);
    throw new HttpError(410, "Address expired");
  }
  return t;
}

const actions = {
  async domains() {
    const d = await smtp("/domains?isActive=true");
    const domains = members(d).filter((x) => x.isActive !== false).map((x) => x.domain);
    if (!domains.length) throw new HttpError(503, "No active domains");
    return { domains };
  },

  async create(input) {
    const local = String(input.local || "").toLowerCase().replace(/[^a-z0-9._-]/g, "").slice(0, 40) || `wisp${Date.now()}`;
    const { domains } = await actions.domains();
    const domain = domains.includes(input.domain) ? input.domain : domains[0];
    const address = `${local}@${domain}`;
    const account = await smtp("/accounts", {
      method: "POST",
      body: { address, password: randomBytes(18).toString("base64url") },
    });
    let boxes = account.mailboxes;
    if (!Array.isArray(boxes) || !boxes.length) boxes = members(await smtp(`/accounts/${account.id}/mailboxes`));
    const inbox = (boxes.find((b) => String(b.path).toUpperCase() === "INBOX") || boxes[0] || {}).id;
    if (!inbox) {
      await destroyAccount(account.id);
      throw new HttpError(502, "Inbox not available");
    }
    const exp = Date.now() + LIFETIME_MS;
    return { address: account.address || address, inbox, exp, total: LIFETIME_MS / 1000, token: sign({ acc: account.id, mbx: inbox, exp }) };
  },

  async messages(input) {
    const t = await session(input);
    const d = await smtp(`/accounts/${t.acc}/mailboxes/${t.mbx}/messages`);
    return {
      messages: members(d).map((m) => ({
        id: m.id,
        from: fmtFrom(m.from),
        subject: m.subject || "(no subject)",
        isRead: !!m.isRead,
        date: m.date || m.createdAt,
      })),
    };
  },

  async message(input) {
    const t = await session(input);
    const id = encodeURIComponent(String(input.id || ""));
    if (!id) throw new HttpError(400, "Missing message id");
    const path = `/accounts/${t.acc}/mailboxes/${t.mbx}/messages/${id}`;
    const m = await smtp(path);
    if (!m.isRead) smtp(path, { method: "PATCH", body: { isRead: true } }).catch(() => {});
    const html = Array.isArray(m.html) ? m.html.join("\n") : m.html;
    return {
      id: m.id,
      from: fmtFrom(m.from),
      subject: m.subject || "(no subject)",
      date: m.date || m.createdAt,
      text: (m.text && String(m.text).trim()) || htmlToText(html) || m.intro || "",
    };
  },

  async delete_message(input) {
    const t = await session(input);
    const id = encodeURIComponent(String(input.id || ""));
    if (!id) throw new HttpError(400, "Missing message id");
    await smtp(`/accounts/${t.acc}/mailboxes/${t.mbx}/messages/${id}`, { method: "DELETE" });
    return { ok: true };
  },

  async extend(input) {
    const t = await session(input);
    const exp = Math.min(t.exp + LIFETIME_MS, Date.now() + MAX_AHEAD_MS);
    return { exp, token: sign({ ...t, exp }) };
  },

  async destroy(input) {
    const t = verify(input.token);
    await destroyAccount(t.acc);
    return { ok: true };
  },
};

export default async (req) => {
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  const action = new URL(req.url).searchParams.get("action");
  const fn = Object.hasOwn(actions, action) ? actions[action] : null;
  if (!fn) return json({ error: "Unknown action" }, 400);
  let input = {};
  try {
    input = (await req.json()) || {};
  } catch {}
  try {
    return json(await fn(input));
  } catch (e) {
    const status = e instanceof HttpError ? e.status : 500;
    if (!(e instanceof HttpError)) console.error(e);
    return json({ error: e instanceof HttpError ? e.message : "Server error" }, status);
  }
};

// Huawei Cloud CodeArts (华为云 CodeArts), as its IDE signs in and talks:
// a Huawei Cloud account signed in at CodeArts' portal (OAuth2 PKCE, the
// token exchange bound to a DPoP key), traded for STS credentials at
// sts.cn-north-4, which sign every request with Huawei's SDK-HMAC-SHA256.
// The models are the account's own: its plan's through the AgentCenter
// channel, and the free daily quota's through opengw.developer.huaweicloud.com,
// which serves them only after the day's claim (the check-in).
import { createHash, createHmac, randomBytes } from "node:crypto"
import { createServer, STATUS_CODES } from "node:http"

const ID = "codearts"
const BASE = "https://snap-access.cn-north-4.myhuaweicloud.com"
const CHAT_PATH = "/api/v2/chat/completions"
const AGENTS_PATH = "/v1/agent-center/agents/useragents"
const AGENT_DETAIL_PATH = "/v1/agent-center/agents/detail"
const OPENGW = "https://opengw.developer.huaweicloud.com"
const CLAIM_PATH = "/api/v1/benefit/claim"
const BALANCE_PATH = "/api/v1/user/tokens/balance"
const CONFIG_PATH = "/api/v1/gateway/config"
const STS_TOKEN_URL = "https://sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens"
const PORTAL = "https://codearts.huaweicloud.com/portal/authorize"
const CLIENT_ID = "codearts-agent"
const PLUGIN_NAME = "snap_AIIDE"
const PLUGIN_VERSION = "5.2.0"
const REDIRECT_PATH = "/oauth/callback"
const UA = "opencode-codearts-auth/0.1.0"

// the STS credentials live about two hours; this close to their end the
// account is signed on again (codearts2api renews at the same lead)
const RENEW_LEAD = 10 * 60 * 1000
// an unknown model reads the account's list again at most this often,
// as the proxy's five-minute model cache does
const MODEL_TTL = 5 * 60 * 1000
const SIGN_IN_TIMEOUT = 5 * 60 * 1000
const ASK_TIMEOUT = 30_000

// the plan's models, and the free quota's, when the account's own list
// can't be read; the free ones are also the ones a model list sync claims
// the day's allowance for. The windows are CodeArts' own (codearts2api's
// models-cache.json).
const FALLBACK_AGENT = ["openpangu-2.0-pro", "openpangu-2.0-flash", "GLM-5.2"]
const FALLBACK_BENEFIT = ["glm-5.3-flash", "deepseek-v4-pro-0813", "deepseek-v4-flash-0731", "deepseek-v4.1-flash"]
const FALLBACK_MODELS = {
  "openpangu-2.0-pro": { name: "openpangu-2.0-pro", limit: { context: 524_288, output: 131_072 } },
  "openpangu-2.0-flash": { name: "openpangu-2.0-flash", limit: { context: 524_288, output: 131_072 } },
  "GLM-5.2": { name: "GLM-5.2", limit: { context: 202_752, output: 131_072 } },
  "glm-5.3-flash": { name: "glm-5.3-flash", limit: { context: 1_048_576, output: 131_072 } },
  "deepseek-v4-pro-0813": { name: "deepseek-v4-pro-0813", limit: { context: 1_000_000, output: 393_216 } },
  "deepseek-v4-flash-0731": { name: "deepseek-v4-flash-0731", limit: { context: 1_048_576, output: 393_216 } },
  "deepseek-v4.1-flash": { name: "deepseek-v4.1-flash", limit: { context: 1_000_000, output: 384_000 } },
}

const parseJSON = (text) => {
  try {
    return JSON.parse(text)
  } catch {
    return undefined
  }
}

// statusLine is a status as Go's HTTP client names it, "502 Bad Gateway".
const statusLine = (status) => `${status} ${STATUS_CODES[status] ?? ""}`.trim()

const b64u = (buf) => Buffer.from(buf).toString("base64url")

// ---- Huawei's SDK-HMAC-SHA256 -------------------------------------------------

// quote is Python's urllib.parse.quote with safe="-_.~", which is what the
// IDE signs with (encodeURIComponent leaves !*'() alone)
const quote = (v) => encodeURIComponent(String(v)).replace(/[!*'()]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase())

// canonicalQuery is the query with its pairs sorted and quoted, "" when
// there is none.
function canonicalQuery(search) {
  const pairs = [...new URLSearchParams(search ?? "")]
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0))
  return pairs.map(([k, v]) => `${quote(k)}=${quote(v)}`).join("&")
}

// sdkDate is the x-sdk-date header's shape, "20261009T123456Z".
const sdkDate = (now = new Date()) => now.toISOString().replace(/[-:]/g, "").replace(/\.\d+/, "")

// sdkHeaders signs one request the way the IDE does: every header name
// lowercased and sorted, the URI with a trailing slash, the query sorted,
// the body's SHA-256, and the whole signed with the secret key.
function sdkHeaders(creds, method, url, body = "", extra = {}, date = sdkDate()) {
  const u = new URL(url)
  const path = u.pathname || "/"
  const headers = { ...extra, host: u.host, "content-type": "application/json", "x-sdk-date": date }
  if (creds?.securityToken) headers["x-security-token"] = creds.securityToken
  const names = Object.keys(headers).sort()
  const canonicalHeaders = names.map((n) => `${n}:${String(headers[n]).trim()}\n`).join("")
  const signed = names.join(";")
  const payload = createHash("sha256").update(body ?? "").digest("hex")
  const canonical = [method.toUpperCase(), path.endsWith("/") ? path : path + "/", canonicalQuery(u.search), canonicalHeaders, signed, payload].join("\n")
  const toSign = `SDK-HMAC-SHA256\n${date}\n${createHash("sha256").update(canonical).digest("hex")}`
  const signature = createHmac("sha256", creds.secretAccessKey).update(toSign).digest("hex")
  headers.Authorization = `SDK-HMAC-SHA256 Access=${creds.accessKeyId}, SignedHeaders=${signed}, Signature=${signature}`
  return headers
}

// ---- the DPoP key and the PKCE pair ------------------------------------------

const P256_N = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")

async function newDpopKey() {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey)
  return { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, d: jwk.d }
}

// dpopProof is the DPoP header of a token request: ES256 over htm/htu with
// the key's public half in the header, and the signature's S the lower of
// the two the curve allows (RFC 9449 as the STS reads it; codearts2api
// normalizes it the same way).
async function dpopProof(jwk, url, now = Date.now()) {
  const key = await crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, d: jwk.d }, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"])
  const head = b64u(JSON.stringify({ alg: "ES256", typ: "dpop+jwt", jwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y } }))
  const body = b64u(JSON.stringify({ htm: "POST", htu: url, iat: Math.floor(now / 1000), jti: randomBytes(16).toString("hex") }))
  const seg = head + "." + body
  const raw = Buffer.from(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new TextEncoder().encode(seg)))
  const r = raw.subarray(0, 32)
  const s = BigInt("0x" + raw.subarray(32, 64).toString("hex"))
  const low = s <= P256_N >> 1n ? raw.subarray(32, 64) : Buffer.from((P256_N - s).toString(16).padStart(64, "0"), "hex")
  return seg + "." + b64u(Buffer.concat([r, low]))
}

function pkce() {
  const verifier = b64u(randomBytes(64))
  return { verifier, challenge: b64u(createHash("sha256").update(verifier).digest()) }
}

// ---- the token endpoint -------------------------------------------------------

// Lapsed is a sign-in the vendor no longer takes: it must be signed in
// again.
class Lapsed extends Error {}

// StsError carries the endpoint's status so its callers can tell a spent
// refresh token (400/401/403) from a hiccup (5xx, the network).
class StsError extends Error {
  constructor(message, status) {
    super(message)
    this.status = status
  }
}

async function sts(form, dpop, signal) {
  const res = await fetch(STS_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", DPoP: await dpopProof(dpop, STS_TOKEN_URL), "User-Agent": UA },
    body: new URLSearchParams(form).toString(),
    signal,
  })
  const text = await res.text()
  const body = parseJSON(text)
  if (res.status >= 400) {
    const why = typeof body?.error_description === "string" ? body.error_description : typeof body?.error === "string" ? body.error : text.slice(0, 200)
    throw new StsError(`the token endpoint answered ${statusLine(res.status)}${why ? `: ${why}` : ""}`, res.status)
  }
  return body ?? {}
}

// credentialsOf reads the token response's credentials, in either of the
// field names its channels use.
function credentialsOf(body) {
  const c = body?.credentials || body?.credential || {}
  return {
    accessKeyId: c.access_key_id || c.access || "",
    secretAccessKey: c.secret_access_key || c.secret || "",
    securityToken: c.security_token || c.securityToken || "",
    expiration: c.expiration || c.expires_at || "",
  }
}

const expiresOf = (creds) => {
  const t = Date.parse(creds?.expiration ?? "")
  return isNaN(t) ? 0 : t
}

// userFromRefreshToken reads the account's identity out of the refresh
// token's own JWT: its user_profile payload carries principal_id (the
// user), account_id (the domain) and account_name. Nothing is verified —
// the identity only names the account.
function userFromRefreshToken(token) {
  const parts = String(token ?? "").split(".")
  if (parts.length < 2) return {}
  const payload = parseJSON(Buffer.from(parts[1], "base64url").toString("utf8")) ?? {}
  const profile = payload.user_profile
  if (typeof profile !== "string" || !profile) return {}
  const p = profile.split(".")
  const u = parseJSON(Buffer.from(p.length >= 2 ? p[1] : p[0], "base64url").toString("utf8")) ?? {}
  return { userId: String(u.principal_id ?? ""), userName: String(u.account_name ?? ""), domainId: String(u.account_id ?? "") }
}

function toAuth(refresh, creds) {
  return { type: "oauth", refresh: JSON.stringify(refresh), access: JSON.stringify(creds), expires: expiresOf(creds), accountId: refresh.userId || "" }
}

// parseAuth is a kept sign-in as the plugin works with it, null for
// anything else.
function parseAuth(auth) {
  if (auth?.type !== "oauth") return null
  const refresh = parseJSON(auth.refresh ?? "{}")
  let creds = {}
  try {
    creds = JSON.parse(auth.access || "{}") ?? {}
  } catch {}
  if (!refresh?.refreshToken || !refresh?.dpop?.d) return null
  return { refresh, creds, expires: Number(auth.expires) || 0, accountId: String(auth.accountId ?? refresh.userId ?? "") }
}

const accountKeyOf = (a) => String(a?.refresh?.userId || a?.refresh?.userName || a?.accountId || "codearts")

// exchange trades the code the portal came back with for the account's
// credentials. The DPoP key made here stays with them: every renewal must
// sign with the same one.
async function exchange(code, verifier, port, dpop) {
  const body = await sts(
    { client_id: CLIENT_ID, code, code_verifier: verifier, grant_type: "authorization_code", redirect_uri: `http://127.0.0.1:${port}${REDIRECT_PATH}` },
    dpop,
    AbortSignal.timeout(ASK_TIMEOUT),
  )
  const creds = credentialsOf(body)
  if (!(creds.accessKeyId && creds.secretAccessKey && creds.securityToken)) throw new Error("the token endpoint sent no credentials")
  let user = { userId: String(body.user_id ?? ""), userName: String(body.user_name ?? ""), domainId: String(body.domain_id ?? "") }
  if (!user.userId) user = { ...user, ...userFromRefreshToken(body.refresh_token) }
  if (!body.refresh_token) throw new Error("the token endpoint sent no refresh token")
  return toAuth({ v: 1, clientId: CLIENT_ID, codeVerifier: verifier, dpop, refreshToken: body.refresh_token, ...user }, creds)
}

// renewTokens trades the refresh token for new credentials. The refresh
// token is spent by the trade and a new one comes back, so what this
// returns must be saved.
async function renewTokens(refresh) {
  let body
  try {
    body = await sts(
      { client_id: refresh.clientId || CLIENT_ID, code_verifier: refresh.codeVerifier, grant_type: "refresh_token", refresh_token: refresh.refreshToken },
      refresh.dpop,
      AbortSignal.timeout(ASK_TIMEOUT),
    )
  } catch (e) {
    if (e instanceof StsError && [400, 401, 403].includes(e.status)) throw new Lapsed(`CodeArts: the sign-in has expired — sign in again (${e.message})`)
    throw e
  }
  const creds = credentialsOf(body)
  if (!(creds.accessKeyId && creds.secretAccessKey && creds.securityToken && body.refresh_token)) throw new Lapsed("CodeArts: the token endpoint sent no credentials back; sign in again")
  return { refresh: { ...refresh, refreshToken: body.refresh_token }, creds, expires: expiresOf(creds) }
}

// ---- the pages the account's own list and quota come from ---------------------

// unwrap checks an opengw answer (error_code 0000 is its success) and
// gives its result. The error carries the business code.
function unwrap(r) {
  if (r.res.status !== 200) throw new Error(`HTTP ${statusLine(r.res.status)}${r.text ? `: ${r.text.slice(0, 200)}` : ""}`)
  const code = r.json?.error_code
  if (code != null && code !== "0000" && code !== 0) {
    const e = new Error(`code ${code}${r.json?.error_msg ? `: ${r.json.error_msg}` : ""}`)
    e.code = code
    throw e
  }
  return r.json?.result ?? {}
}

const AGENT_HEADERS = { "agent-type": "AgentCenter", "x-language": "zh-cn", accept: "application/json" }

const tokens = (n) => {
  for (const [d, u] of [[1e9, "B"], [1e6, "M"], [1e3, "K"]]) {
    if (n >= d) return `${Number((n / d).toPrecision(3))}${u}`
  }
  return String(n)
}

// beijingDay is the day at the account's vendor, which books its daily
// allowance by Beijing days ("2026-10-09").
const beijingDay = (ms) => new Date(ms).toLocaleDateString("en-CA", { timeZone: "Asia/Shanghai" })

const nextBeijingMidnight = (now = Date.now()) => new Date(Date.parse(`${beijingDay(now)}T00:00:00+08:00`) + 24 * 3600 * 1000).toISOString()

const modelInfo = (m) => ({
  id: m.id,
  name: m.name || m.id,
  limit: { context: m.context ?? 0, output: m.output ?? 0 },
  tool_call: true,
  reasoning: true,
  attachment: !!m.images,
  modalities: { input: m.images ? ["text", "image"] : ["text"], output: ["text"] },
})

const errorResponse = (status, message) =>
  new Response(JSON.stringify({ error: { message, type: "api_error", code: null } }), { status, headers: { "content-type": "application/json" } })

// said is an answer with magpie's X-Magpie-Sign-In, which tells what it
// means for the account's sign-in whatever its status: "expired" marks it
// lapsed, "renewed" took a lapse mark off. magpie takes it off before the
// agent sees it.
const said = (res, v) => {
  const h = new Headers(res.headers)
  h.set("X-Magpie-Sign-In", v)
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h })
}

// ---- the browser sign-in ------------------------------------------------------

const page = (ok, title, text) => `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${title}</title>
<style>body{font:15px/1.5 -apple-system,system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;background:#f6f6f4;color:#222}
@media(prefers-color-scheme:dark){body{background:#1c1c1c;color:#eee}}main{max-width:420px;padding:24px}h1{font-size:20px;margin:0 0 8px}p{margin:0;opacity:.75}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:8px;background:${ok ? "#2a9d58" : "#d1453b"}}</style>
<main><h1><span class="dot"></span>${title}</h1><p>${String(text).replace(/[<>&]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" })[c])}</p></main>`

// browserSignIn is the IDE's own sign-in: CodeArts' portal page takes the
// browser, which comes back to a callback on 127.0.0.1 with the code. The
// portal calls back twice: the first carries the page to go on with, the
// second the code.
async function browserSignIn() {
  const { verifier, challenge } = pkce()
  const dpop = await newDpopKey()
  let port = 0
  let over = false
  let settle
  const done = new Promise((r) => (settle = r))
  const finish = (result) => {
    if (over) return
    over = true
    settle(result)
  }
  const server = createServer(async (req, res) => {
    const html = (ok, title, text) => {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" })
      res.end(page(ok, title, text))
    }
    const url = new URL(req.url ?? "/", "http://127.0.0.1")
    if (url.pathname !== REDIRECT_PATH) return res.writeHead(404).end()
    const q = url.searchParams
    const redirect = q.get("redirect")
    if (!q.get("code") && redirect && /^https?:\/\//i.test(redirect)) {
      res.writeHead(307, { Location: redirect }).end()
      return
    }
    if (over) return html(false, "This sign-in is over", "Start it again in magpie.")
    const code = q.get("code") ?? ""
    if (!code) {
      finish({ type: "failed", error: "the sign-in page came back with no code" })
      return html(false, "Sign-in didn't finish", "The page came back with no code; start the sign-in again.")
    }
    try {
      const auth = await exchange(code, verifier, port, dpop)
      finish({ ...auth, type: "success" })
      html(true, "You're signed in", `${auth.accountId || "The account"} is signed in. You can close this tab.`)
    } catch (e) {
      finish({ type: "failed", error: e?.message ?? String(e) })
      html(false, "Sign-in didn't finish", e?.message ?? String(e))
    }
  })
  await new Promise((resolve, reject) => {
    server.once("error", reject)
    server.listen(0, "127.0.0.1", resolve)
  })
  port = server.address().port
  const q = new URLSearchParams({
    theme: "2",
    locale: "zh-cn",
    uri_scheme: CLIENT_ID,
    client_id: CLIENT_ID,
    port: String(port),
    code_challenge: challenge,
    code_challenge_method: "SHA-256",
    ticket_id: randomBytes(16).toString("hex"),
    "plugin-name": PLUGIN_NAME,
    "plugin-version": PLUGIN_VERSION,
  })
  const timer = setTimeout(() => finish({ type: "failed", error: "the sign-in timed out; start it again" }), SIGN_IN_TIMEOUT)
  done.then(() => {
    clearTimeout(timer)
    setTimeout(() => server.close(), 5_000).unref?.()
  })
  return {
    url: `${PORTAL}?${q}`,
    instructions: "Sign in with your Huawei Cloud account (华为云账号) in the browser and allow the sign-in. It finishes here by itself.",
    method: "auto",
    callback: () => done,
  }
}

// codeIn is the code in what was pasted: the callback's address, or the
// code alone.
const codeIn = (text) => {
  const s = String(text ?? "").trim()
  if (!s || /\s/.test(s)) return ""
  const m = /[?&]code=([^&]+)/.exec(s)
  try {
    return m ? decodeURIComponent(m[1]) : s
  } catch {
    return m ? m[1] : s
  }
}

// codeSignIn is the same sign-in for a browser that can't reach this
// machine's callback (a magpie on a server): the page the browser ends on
// shows the code in its address, and what is pasted back into magpie
// finishes the sign-in.
async function codeSignIn() {
  const { verifier, challenge } = pkce()
  const dpop = await newDpopKey()
  let port = 0
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1")
    if (url.pathname !== REDIRECT_PATH) return res.writeHead(404).end()
    const q = url.searchParams
    const redirect = q.get("redirect")
    if (!q.get("code") && redirect && /^https?:\/\//i.test(redirect)) {
      res.writeHead(307, { Location: redirect }).end()
      return
    }
    // the address of this page carries the code, and it is what gets
    // pasted back, so the page says so
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" })
    res.end(page(true, "Copy this page's address", "Paste the address of this page (or the code in it) into magpie to finish the sign-in."))
  })
  await new Promise((resolve, reject) => {
    server.once("error", reject)
    server.listen(0, "127.0.0.1", resolve)
  })
  port = server.address().port
  const q = new URLSearchParams({
    theme: "2",
    locale: "zh-cn",
    uri_scheme: CLIENT_ID,
    client_id: CLIENT_ID,
    port: String(port),
    code_challenge: challenge,
    code_challenge_method: "SHA-256",
    ticket_id: randomBytes(16).toString("hex"),
    "plugin-name": PLUGIN_NAME,
    "plugin-version": PLUGIN_VERSION,
  })
  const timer = setTimeout(() => server.close(), SIGN_IN_TIMEOUT)
  timer.unref?.()
  return {
    url: `${PORTAL}?${q}`,
    instructions: "Sign in with your Huawei Cloud account (华为云账号) in the browser. The page it ends on may not load here: copy its address and paste it into magpie (the code in it is enough).",
    method: "code",
    callback: async (pasted) => {
      try {
        const code = codeIn(pasted)
        if (!code) return { type: "failed", error: "no code in what was pasted; paste the sign-in page's address" }
        const auth = await exchange(code, verifier, port, dpop)
        return { ...auth, type: "success" }
      } catch (e) {
        return { type: "failed", error: e?.message ?? String(e) }
      } finally {
        clearTimeout(timer)
        setTimeout(() => server.close(), 5_000).unref?.()
      }
    },
  }
}

// ---- the plugin ---------------------------------------------------------------

export const CodeArtsAuthPlugin = async ({ client } = {}) => {
  // renewals under way, one to an account, and the last session each
  // account got here, so magpie's auth.refresh handed a sign-in from
  // before it gives that one rather than spending the refresh token again
  const renewing = new Map()
  const renewed = new Map()
  // the plan's model ids each account was last seen with
  const agentIds = new Map()

  const save = async (auth) => {
    try {
      await client?.auth?.set?.({ path: { id: ID }, body: auth })
    } catch {}
  }

  const renew = (a, keep) => {
    const who = accountKeyOf(a)
    let r = renewing.get(who)
    if (!r) {
      r = (async () => {
        const got = await renewTokens(a.refresh)
        const at = { ...got, renewed: true }
        renewed.set(who, at)
        if (keep) await save(toAuth(got.refresh, got.creds))
        return at
      })().finally(() => renewing.delete(who))
      renewing.set(who, r)
    }
    return r
  }

  // session is the account with live credentials: renewed when they are
  // RENEW_LEAD from their expiry, or when force says (the upstream turned
  // the last ones away). A hiccup on the renewal leaves the credentials in
  // hand, for the vendor's answer to tell.
  const session = async (a, force) => {
    if (!force && a.creds.accessKeyId && Date.now() < a.expires - RENEW_LEAD) return a
    try {
      return await renew(a, true)
    } catch (e) {
      if (!(e instanceof Lapsed) && !force && a.creds.accessKeyId) return a
      throw e
    }
  }

  const fresh = async (getAuth, force) => {
    const a = parseAuth(await getAuth())
    if (!a) throw new Lapsed("CodeArts: not signed in")
    return session(a, force)
  }

  // ask sends one signed request as the account and gives its answer,
  // parsed.
  const ask = async (creds, method, url, body = "", extra = {}) => {
    const headers = sdkHeaders(creds, method, url, body, extra)
    const res = await fetch(url, { method, headers, body: method === "GET" || method === "HEAD" ? undefined : body, signal: AbortSignal.timeout(ASK_TIMEOUT) })
    const text = await res.text()
    return { res, text, json: parseJSON(text) }
  }

  // agentModels reads the plan's models: the account's agents, then the
  // first of them that lists models.
  const agentModels = async (creds) => {
    const list = await ask(creds, "GET", `${BASE}${AGENTS_PATH}?offset=0&limit=100`, "", AGENT_HEADERS)
    if (list.res.status !== 200) throw new Error(`the model list answered ${statusLine(list.res.status)}`)
    const agents = [...(list.json?.agents ?? [])].sort(
      (x, y) => Number(!x?.is_primary_agent) - Number(!y?.is_primary_agent) || (x?.agent_order ?? 999999) - (y?.agent_order ?? 999999),
    )
    const out = []
    for (const agent of agents) {
      if (!agent?.agent_id) continue
      const url = `${BASE}${AGENT_DETAIL_PATH}?agent_id=${encodeURIComponent(agent.agent_id)}`
      const detail = await ask(creds, "GET", url, "", AGENT_HEADERS)
      if (detail.res.status !== 200) continue
      for (const m of detail.json?.gpts?.models ?? []) {
        const id = m?.model_id || m?.model_alias
        if (!id || out.some((x) => x.id === id)) continue
        const p = m?.model_parameters ?? {}
        out.push({ id, name: m.model_alias || m.model_name || id, channel: "agent", context: p.context_window ?? 0, output: p.max_tokens ?? 0, images: !!p.supports_images })
      }
      if (out.length) break
    }
    return out
  }

  const claimStatus = (creds) => ask(creds, "GET", OPENGW + CLAIM_PATH).then(unwrap)
  const claimNow = (creds) => ask(creds, "POST", OPENGW + CLAIM_PATH).then(unwrap)
  const balanceOf = (creds) => ask(creds, "GET", OPENGW + BALANCE_PATH).then(unwrap)

  // benefitModels reads the free quota's models from opengw. The day's
  // allowance is claimed first, as the proxy does: unclaimed, those models
  // answer "benefit not found". A claim that fails (already claimed, most
  // days) leaves the list alone.
  const benefitModels = async (creds) => {
    try {
      await claimNow(creds)
    } catch {}
    const r = await ask(creds, "GET", OPENGW + CONFIG_PATH)
    const result = unwrap(r)
    const out = []
    for (const m of result?.models ?? []) {
      const id = m?.model_id
      if (!id || out.some((x) => x.id === id)) continue
      out.push({ id, name: m.model_name || id, channel: "benefit", context: m.context_window ?? 0, output: m.max_tokens ?? 0, images: false })
    }
    return out
  }

  // accountModels is the account's own list: the plan's models, then the
  // free quota's. A free list that can't be read falls back to the ones
  // the config declares, as the proxy falls back to its own list.
  const accountModels = async (creds) => {
    const plan = await agentModels(creds)
    let free = await benefitModels(creds).catch(() => [])
    if (!free.length) free = FALLBACK_BENEFIT.map((id) => ({ id, name: FALLBACK_MODELS[id]?.name ?? id, channel: "benefit", context: FALLBACK_MODELS[id]?.limit.context ?? 0, output: FALLBACK_MODELS[id]?.limit.output ?? 0 }))
    const known = new Set(plan.map((m) => m.id))
    return [...plan, ...free.filter((m) => !known.has(m.id))]
  }

  const rememberAgents = (a, list) => agentIds.set(accountKeyOf(a), { ids: new Set(list.filter((m) => m.channel === "agent").map((m) => m.id)), at: Date.now() })

  // channelOf is which channel serves a model: the plan's (AgentCenter,
  // the plain signature) or the free quota's (opengw, whose models must be
  // asked with maas_type/model-id/model-name signed in). A model not known
  // to be the plan's goes as a free one, as the proxy decides it; the
  // account's list is read again first when the last read is stale.
  const channelOf = async (s, model) => {
    if (!model) return "benefit"
    const who = accountKeyOf(s)
    let have = agentIds.get(who)
    if (have?.ids.has(model)) return "agent"
    if (!have || Date.now() - have.at > MODEL_TTL) {
      try {
        const list = await agentModels(s.creds)
        have = { ids: new Set(list.map((m) => m.id)), at: Date.now() }
        agentIds.set(who, have)
        if (have.ids.has(model)) return "agent"
      } catch {
        // the read failed: the model goes as a free one, and the next try
        // waits the TTL out
        agentIds.set(who, { ids: have?.ids ?? new Set(FALLBACK_AGENT), at: Date.now() })
      }
    }
    return "benefit"
  }

  // usage is the free quota's balance, magpie's own hook. The quota is the
  // day's, claimed by the check-in and spent by the free models.
  const usage = async (getAuth) => {
    let s
    try {
      s = await fresh(getAuth, false)
    } catch (e) {
      return { error: e?.message ?? String(e), signIn: e instanceof Lapsed ? "expired" : "kept" }
    }
    const signIn = s.renewed ? "renewed" : "kept"
    const user = s.refresh.userName || s.refresh.userId || ""
    try {
      const info = await balanceOf(s.creds)
      const total = Number(info?.total_quota) || 0
      const left = Number(info?.total_balance) || 0
      const used = Number(info?.used_amount) || 0
      if (!total) return { user, signIn, balance: "no free quota claimed" }
      return {
        user,
        signIn,
        balance: `${tokens(left)} / ${tokens(total)} tokens left`,
        windows: [
          {
            name: "Free quota · daily",
            used: Math.max(0, Math.min(100, (100 * used) / total)),
            amount: used,
            limit: total,
            unit: "tokens",
            resetsAt: nextBeijingMidnight(),
            span: 24 * 3600,
            display: `${tokens(left)} / ${tokens(total)} tokens left`,
          },
        ],
      }
    } catch (e) {
      return { user, error: `CodeArts' free quota: ${e?.message ?? e}`, signIn }
    }
  }

  // checkin presses the day's claim, magpie's own hook: the free models
  // are only served once it is in. Its answer is the day's claim, and the
  // balance that comes with it.
  const checkin = async (getAuth) => {
    const s = await fresh(getAuth, false)
    const today = beijingDay(Date.now())
    const status = await claimStatus(s.creds)
    const last = Number(status?.create_time) || 0
    if (last && beijingDay(last) === today) return { outcome: "done", message: `checked in at ${new Date(last).toLocaleString("en-GB", { timeZone: "Asia/Shanghai" })}` }
    let claimed
    try {
      claimed = await claimNow(s.creds)
    } catch (e) {
      // already claimed (4006), which is what most days answer
      if (String(e?.code) === "4006") return { outcome: "done", message: "already checked in today" }
      throw e
    }
    const info = await balanceOf(s.creds).catch(() => null)
    const total = Number(info?.total_quota) || 0
    const left = Number(info?.total_balance) || 0
    const balance = total ? `free quota ${tokens(left)} / ${tokens(total)} tokens left` : ""
    const when = Number(claimed?.create_time) || 0
    if (!when || beijingDay(when) !== today) return { outcome: "done", ...(balance ? { message: balance } : {}) }
    return { outcome: "claimed", credit: total, ...(balance ? { message: balance } : {}) }
  }

  // refresh is magpie's auth.refresh: the credentials renewed RENEW_LEAD
  // before they end, as the fields that changed. A refresh token the STS
  // no longer takes is signIn "expired"; any other failure throws as it is.
  const refresh = async (auth) => {
    const a = parseAuth(auth)
    if (!a) return undefined
    const last = renewed.get(accountKeyOf(a))
    if (last && last.expires > a.expires && Date.now() < last.expires - RENEW_LEAD) {
      return { access: JSON.stringify(last.creds), refresh: JSON.stringify(last.refresh), expires: last.expires }
    }
    try {
      const s = await renew(a, false)
      return { access: JSON.stringify(s.creds), refresh: JSON.stringify(s.refresh), expires: s.expires }
    } catch (e) {
      if (e instanceof Lapsed) throw Object.assign(new Error(e.message), { signIn: "expired" })
      throw e
    }
  }

  return {
    config: async (config) => {
      config.provider ??= {}
      const was = config.provider[ID] ?? {}
      config.provider[ID] = {
        name: "CodeArts",
        npm: "@ai-sdk/openai-compatible",
        api: BASE + "/api/v2",
        ...was,
        models: { ...FALLBACK_MODELS, ...(was.models ?? {}) },
      }
    },
    auth: {
      provider: ID,
      usage,
      checkin,
      // the credentials live about two hours; magpie signs the account on
      // again this long before their end, once, before its requests,
      // models and usage ask (session's own check stays for OpenCode)
      refreshLead: RENEW_LEAD,
      refresh,
      loader: async (getAuth) => {
        const a = parseAuth(await getAuth())
        if (!a) return {}
        return {
          baseURL: BASE + "/api/v2",
          apiKey: "codearts", // the SDK's placeholder; the signature is the authorization
          async fetch(input, init = {}) {
            const req = input instanceof Request ? input : null
            const url = req ? req.url : String(input)
            let body = init.body ?? (req ? await req.text() : undefined)
            if (body instanceof ArrayBuffer) body = new TextDecoder().decode(body)
            else if (ArrayBuffer.isView(body)) body = new TextDecoder().decode(new Uint8Array(body.buffer, body.byteOffset, body.byteLength))
            const model = typeof body === "string" ? (parseJSON(body)?.model ?? "") : ""
            let s
            try {
              s = await session(a, false)
            } catch (e) {
              if (!(e instanceof Lapsed)) throw e
              return said(errorResponse(502, e.message), "expired")
            }
            let renewed = !!s.renewed
            const send = async (creds) => {
              const channel = await channelOf(s, model)
              // the free quota's models must be asked with these three
              // signed in; the plan's answer "unsupported model" with them
              const extra = channel === "benefit" && model ? { maas_type: "benefit", "model-id": model, "model-name": model } : {}
              const method = init.method ?? req?.method ?? "POST"
              const headers = sdkHeaders(creds, method, url, body, extra)
              return fetch(url, { method, headers, body: method === "GET" || method === "HEAD" ? undefined : body, signal: init.signal ?? req?.signal })
            }
            let res = await send(s.creds)
            // credentials spent before their time (or a clock off by more
            // than the lead): renewed once and the request sent again; a
            // renewal that failed leaves the answer as it came
            if (res.status === 401 || res.status === 403) {
              let again = null
              try {
                again = await session(s, true)
              } catch (e) {
                if (e instanceof Lapsed) {
                  await res.arrayBuffer().catch(() => {})
                  return said(errorResponse(502, e.message), "expired")
                }
              }
              if (again && again.creds.securityToken !== s.creds.securityToken) {
                await res.arrayBuffer().catch(() => {})
                renewed = true
                res = await send(again.creds)
              }
            }
            return said(res, renewed ? "renewed" : "kept")
          },
        }
      },
      methods: [
        { type: "oauth", label: "Huawei Cloud account (browser)", authorize: () => browserSignIn() },
        { type: "oauth", label: "Huawei Cloud account (paste the callback URL)", authorize: () => codeSignIn() },
      ],
    },
    provider: {
      id: ID,
      // models is the account's own list, the one its plan and free quota
      // give; the fallback the config declares stands when it can't be
      // read. A sign-in the vendor refused is marked.
      async models(provider, { auth } = {}) {
        const given = provider?.models ?? {}
        const a = parseAuth(auth)
        if (!a) return given
        let s
        try {
          s = await session(a, false)
        } catch (e) {
          if (e instanceof Lapsed) throw Object.assign(new Error(e.message), { signIn: "expired" })
          throw e
        }
        const list = await accountModels(s.creds)
        rememberAgents(s, list)
        return Object.fromEntries(list.map((m) => [m.id, modelInfo(m)]))
      },
    },
  }
}

// for tests
export const _internal = {
  sdkHeaders,
  sdkDate,
  canonicalQuery,
  quote,
  dpopProof,
  newDpopKey,
  pkce,
  sts,
  exchange,
  renewTokens,
  parseAuth,
  toAuth,
  userFromRefreshToken,
  credentialsOf,
  expiresOf,
  unwrap,
  beijingDay,
  nextBeijingMidnight,
  tokens,
  modelInfo,
  page,
  codeIn,
}

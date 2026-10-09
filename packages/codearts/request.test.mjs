// A chat goes to CodeArts' chat endpoint with the account's credentials
// signed in: the plan's models with the plain signature, the free quota's
// with maas_type/model-id/model-name as well. Credentials near their end
// are renewed before the request and saved, one the upstream turns away
// (401/403) is renewed and the request sent once more, and a refresh token
// the STS no longer takes marks the sign-in, as magpie's X-Magpie-Sign-In
// reads it.
import "./nonet.mjs"
import { afterEach, expect, test } from "bun:test"
import { CodeArtsAuthPlugin, _internal } from "./index.mjs"

const real = globalThis.fetch
afterEach(() => (globalThis.fetch = real))

const CHAT = "https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions"
const STS = "https://sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens"
const AGENTS = "https://snap-access.cn-north-4.myhuaweicloud.com/v1/agent-center/agents/useragents?offset=0&limit=100"
const dpop = await _internal.newDpopKey()

const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } })

const access = (expires) => ({ accessKeyId: "AK-1", secretAccessKey: "SK-1", securityToken: "ST-1", expiration: new Date(expires).toISOString() })
const stored = (expires) => _internal.toAuth({ v: 1, clientId: "codearts-agent", codeVerifier: "verifier-1", dpop, refreshToken: "r-1", userId: "u-1" }, access(expires))

function serve(handler) {
  const s = { calls: [], saves: [] }
  globalThis.fetch = async (url, init = {}) => {
    const call = { url: String(url), method: init.method ?? "GET", body: init.body, headers: new Headers(init.headers) }
    s.calls.push(call)
    return handler(call, s)
  }
  s.client = { auth: { set: async ({ body }) => s.saves.push(body) } }
  return s
}

const agentPages = (call) => {
  if (call.url === AGENTS) return json({ agents: [{ agent_id: "a-1", is_primary_agent: true }] })
  if (call.url.includes("/agents/detail")) return json({ gpts: { models: [{ model_id: "openpangu-2.0-pro", model_parameters: { context_window: 524288, max_tokens: 131072 } }] } })
  return null
}

test("the loader gives the chat base URL, and a free model's chat is asked with the three headers", async () => {
  const s = serve((call) => agentPages(call) ?? json({ choices: [] }))
  const hooks = await CodeArtsAuthPlugin({ client: s.client })
  const o = await hooks.auth.loader(async () => stored(Date.now() + 3600_000))
  expect(o.baseURL).toBe("https://snap-access.cn-north-4.myhuaweicloud.com/api/v2")
  expect(o.apiKey).toBe("codearts")
  const body = JSON.stringify({ model: "glm-5.3-flash", messages: [{ role: "user", content: "hi" }], stream: true })
  const res = await o.fetch(CHAT, { method: "POST", headers: { authorization: "Bearer codearts" }, body })
  expect(res.status).toBe(200)
  expect(res.headers.get("X-Magpie-Sign-In")).toBe("kept")
  const chat = s.calls.find((c) => c.url === CHAT)
  expect(chat.headers.get("maas_type")).toBe("benefit")
  expect(chat.headers.get("model-id")).toBe("glm-5.3-flash")
  expect(chat.headers.get("model-name")).toBe("glm-5.3-flash")
  expect(chat.headers.get("x-security-token")).toBe("ST-1")
  // the signature is the one this body and these headers make
  const again = _internal.sdkHeaders(access(Date.now() + 3600_000), "POST", CHAT, body, { maas_type: "benefit", "model-id": "glm-5.3-flash", "model-name": "glm-5.3-flash" }, chat.headers.get("x-sdk-date"))
  expect(chat.headers.get("authorization")).toBe(again.Authorization)
  // the account's list was read once, to tell the channels apart
  expect(s.calls.filter((c) => c.url === AGENTS).length).toBe(1)
})

test("a model the plan lists goes without them", async () => {
  const s = serve((call) => agentPages(call) ?? json({ choices: [] }))
  const hooks = await CodeArtsAuthPlugin({ client: s.client })
  const o = await hooks.auth.loader(async () => stored(Date.now() + 3600_000))
  const res = await o.fetch(CHAT, { method: "POST", body: JSON.stringify({ model: "openpangu-2.0-pro", messages: [] }) })
  expect(res.status).toBe(200)
  const chat = s.calls.find((c) => c.url === CHAT)
  expect(chat.headers.get("maas_type")).toBeNull()
  expect(chat.headers.get("model-id")).toBeNull()
})

test("credentials near their end are renewed before the request, and saved", async () => {
  const s = serve((call) => {
    if (call.url === STS) return json({ credentials: { access_key_id: "AK-2", secret_access_key: "SK-2", security_token: "ST-2", expiration: new Date(Date.now() + 7200_000).toISOString() }, refresh_token: "r-2" })
    if (call.url === CHAT) return json({ choices: [] })
    throw new Error("unexpected " + call.url)
  })
  const hooks = await CodeArtsAuthPlugin({ client: s.client })
  const o = await hooks.auth.loader(async () => stored(Date.now() + 60_000))
  const res = await o.fetch(CHAT, { method: "POST", body: JSON.stringify({ model: "openpangu-2.0-pro", messages: [] }) })
  expect(res.headers.get("X-Magpie-Sign-In")).toBe("renewed")
  expect(s.calls.find((c) => c.url === CHAT).headers.get("x-security-token")).toBe("ST-2")
  expect(JSON.parse(s.saves[0].refresh).refreshToken).toBe("r-2")
})

test("a 401 is renewed once and the request sent again", async () => {
  let chats = 0
  const s = serve((call) => {
    if (call.url === STS) return json({ credentials: { access_key_id: "AK-2", secret_access_key: "SK-2", security_token: "ST-2", expiration: new Date(Date.now() + 7200_000).toISOString() }, refresh_token: "r-2" })
    if (call.url === CHAT) return ++chats === 1 ? json({ error: "the security token has expired" }, 401) : json({ choices: [] })
    throw new Error("unexpected " + call.url)
  })
  const hooks = await CodeArtsAuthPlugin({ client: s.client })
  const o = await hooks.auth.loader(async () => stored(Date.now() + 3600_000))
  const res = await o.fetch(CHAT, { method: "POST", body: JSON.stringify({ model: "openpangu-2.0-pro", messages: [] }) })
  expect(chats).toBe(2)
  expect(res.status).toBe(200)
  expect(res.headers.get("X-Magpie-Sign-In")).toBe("renewed")
  expect(s.saves.length).toBe(1)
})

test("a refresh token the STS no longer takes marks the sign-in expired", async () => {
  const s = serve((call) => {
    if (call.url === STS) return json({ error: "invalid_grant" }, 400)
    throw new Error("unexpected " + call.url)
  })
  const hooks = await CodeArtsAuthPlugin({ client: s.client })
  const o = await hooks.auth.loader(async () => stored(Date.now() - 1000))
  const res = await o.fetch(CHAT, { method: "POST", body: JSON.stringify({ model: "openpangu-2.0-pro", messages: [] }) })
  expect(res.status).toBe(502)
  expect(res.headers.get("X-Magpie-Sign-In")).toBe("expired")
  expect((await res.json()).error.message).toContain("sign in again")
})

test("a sign-in that isn't there yet gives the loader nothing", async () => {
  const hooks = await CodeArtsAuthPlugin({ client: {} })
  expect(await hooks.auth.loader(async () => undefined)).toEqual({})
})

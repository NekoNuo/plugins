// The account's own pages: its model list (the plan's through AgentCenter,
// the free quota's from opengw — claimed first, as the IDE and the proxy
// claim it), the check-in that claims the day's allowance, and the free
// quota's balance as usage.
import "./nonet.mjs"
import { afterEach, expect, test } from "bun:test"
import { CodeArtsAuthPlugin, _internal } from "./index.mjs"

const real = globalThis.fetch
afterEach(() => (globalThis.fetch = real))

const AGENTS = "https://snap-access.cn-north-4.myhuaweicloud.com/v1/agent-center/agents/useragents?offset=0&limit=100"
const DETAIL = "https://snap-access.cn-north-4.myhuaweicloud.com/v1/agent-center/agents/detail?agent_id=a-1"
const CLAIM = "https://opengw.developer.huaweicloud.com/api/v1/benefit/claim"
const CONFIG = "https://opengw.developer.huaweicloud.com/api/v1/gateway/config"
const BALANCE = "https://opengw.developer.huaweicloud.com/api/v1/user/tokens/balance"
const dpop = await _internal.newDpopKey()

const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } })
const ok = (result) => json({ error_code: "0000", result })

const access = (expires) => ({ accessKeyId: "AK-1", secretAccessKey: "SK-1", securityToken: "ST-1", expiration: new Date(expires).toISOString() })
const stored = (expires = Date.now() + 3600_000) => _internal.toAuth({ v: 1, clientId: "codearts-agent", codeVerifier: "verifier-1", dpop, refreshToken: "r-1", userId: "u-1", userName: "Ann" }, access(expires))

function serve(handler) {
  const s = { calls: [] }
  globalThis.fetch = async (url, init = {}) => {
    const call = { url: String(url), method: init.method ?? "GET", body: init.body, headers: new Headers(init.headers) }
    s.calls.push(call)
    return handler(call, s)
  }
  s.client = { auth: { set: async () => {} } }
  return s
}

test("the model list is the plan's and the free quota's, in the account's own windows", async () => {
  const s = serve((call) => {
    if (call.url === AGENTS) return json({ agents: [{ agent_id: "a-1", is_primary_agent: true }, { agent_id: "a-2" }] })
    if (call.url === DETAIL) return json({ gpts: { models: [
      { model_id: "openpangu-2.0-pro", model_alias: "openPangu Pro", model_parameters: { context_window: 524288, max_tokens: 131072, supports_images: true } },
      { model_id: "GLM-5.2", model_parameters: {} },
    ] } })
    if (call.url === CLAIM) return ok({})
    if (call.url === CONFIG) return ok({ models: [
      { model_id: "glm-5.3-flash", model_name: "GLM-5.3 Flash", context_window: 1048576, max_tokens: 131072 },
      { model_id: "openpangu-2.0-pro" },
    ] })
    throw new Error("unexpected " + call.url)
  })
  const hooks = await CodeArtsAuthPlugin({ client: s.client })
  const out = await hooks.provider.models({ models: { "openpangu-2.0-pro": { name: "the config's" } } }, { auth: stored() })
  expect(Object.keys(out)).toEqual(["openpangu-2.0-pro", "GLM-5.2", "glm-5.3-flash"])
  expect(out["openpangu-2.0-pro"].name).toBe("openPangu Pro")
  expect(out["openpangu-2.0-pro"].limit).toEqual({ context: 524288, output: 131072 })
  expect(out["openpangu-2.0-pro"].attachment).toBe(true)
  expect(out["GLM-5.2"].name).toBe("GLM-5.2")
  expect(out["glm-5.3-flash"].name).toBe("GLM-5.3 Flash")
  expect(out["glm-5.3-flash"].limit.context).toBe(1048576)
  // the day's allowance was claimed before the free list was read
  const claim = s.calls.findIndex((c) => c.url === CLAIM && c.method === "POST")
  const config = s.calls.findIndex((c) => c.url === CONFIG)
  expect(claim).toBeGreaterThan(-1)
  expect(claim).toBeLessThan(config)
})

test("a free list that can't be read falls back to the config's own", async () => {
  serve((call) => {
    if (call.url === AGENTS) return json({ agents: [{ agent_id: "a-1" }] })
    if (call.url === DETAIL) return json({ gpts: { models: [{ model_id: "GLM-5.2", model_parameters: {} }] } })
    if (call.url === CLAIM) return ok({})
    if (call.url === CONFIG) return json({ error_code: "5001", error_msg: "busy" })
    throw new Error("unexpected " + call.url)
  })
  const hooks = await CodeArtsAuthPlugin({ client: {} })
  const out = await hooks.provider.models({ models: {} }, { auth: stored() })
  expect(Object.keys(out)).toEqual(["GLM-5.2", "glm-5.3-flash", "deepseek-v4-pro-0813", "deepseek-v4-flash-0731", "deepseek-v4.1-flash"])
})

test("a sign-in the STS no longer takes is marked expired", async () => {
  serve(() => json({ error: "invalid_grant" }, 400))
  const hooks = await CodeArtsAuthPlugin({ client: {} })
  let threw
  try {
    await hooks.provider.models({ models: {} }, { auth: stored(Date.now() - 1000) })
  } catch (e) {
    threw = e
  }
  expect(threw?.signIn).toBe("expired")
})

test("a day already claimed is done", async () => {
  const at = Date.now()
  serve((call) => {
    if (call.url === CLAIM && call.method === "GET") return ok({ create_time: at })
    throw new Error("unexpected " + call.url)
  })
  const hooks = await CodeArtsAuthPlugin({ client: {} })
  const got = await hooks.auth.checkin(async () => stored())
  expect(got.outcome).toBe("done")
})

test("a day not yet claimed is claimed, with the balance it leaves", async () => {
  const s = serve((call) => {
    if (call.url === CLAIM && call.method === "GET") return ok({ create_time: Date.now() - 86400_000 })
    if (call.url === CLAIM && call.method === "POST") return ok({ create_time: Date.now() })
    if (call.url === BALANCE) return ok({ total_quota: 10_000_000, total_balance: 9_500_000, used_amount: 500_000 })
    throw new Error("unexpected " + call.url)
  })
  const hooks = await CodeArtsAuthPlugin({ client: {} })
  const got = await hooks.auth.checkin(async () => stored())
  expect(got.outcome).toBe("claimed")
  expect(got.credit).toBe(10_000_000)
  expect(got.message).toBe("free quota 9.5M / 10M tokens left")
  expect(s.calls.filter((c) => c.url === CLAIM).length).toBe(2)
})

test("a claim that answers 4006 is a day already in", async () => {
  serve((call) => {
    if (call.url === CLAIM && call.method === "GET") return ok({})
    if (call.url === CLAIM && call.method === "POST") return json({ error_code: "4006", error_msg: "already claimed" })
    throw new Error("unexpected " + call.url)
  })
  const hooks = await CodeArtsAuthPlugin({ client: {} })
  const got = await hooks.auth.checkin(async () => stored())
  expect(got.outcome).toBe("done")
  expect(got.message).toBe("already checked in today")
})

test("a claim that fails is a failure", async () => {
  serve((call) => {
    if (call.url === CLAIM && call.method === "GET") return ok({})
    if (call.url === CLAIM && call.method === "POST") return json({ error_code: "5001", error_msg: "busy" }, 500)
    throw new Error("unexpected " + call.url)
  })
  const hooks = await CodeArtsAuthPlugin({ client: {} })
  let threw
  try {
    await hooks.auth.checkin(async () => stored())
  } catch (e) {
    threw = e
  }
  expect(threw).toBeTruthy()
})

test("usage is the free quota's balance, as a day's window", async () => {
  serve((call) => {
    if (call.url === BALANCE) return ok({ total_quota: 10_000_000, total_balance: 9_500_000, used_amount: 500_000 })
    throw new Error("unexpected " + call.url)
  })
  const hooks = await CodeArtsAuthPlugin({ client: {} })
  const u = await hooks.auth.usage(async () => stored())
  expect(u.user).toBe("Ann")
  expect(u.signIn).toBe("kept")
  expect(u.balance).toBe("9.5M / 10M tokens left")
  expect(u.windows[0].name).toBe("Free quota · daily")
  expect(u.windows[0].used).toBeCloseTo(5)
  expect(u.windows[0].amount).toBe(500_000)
  expect(u.windows[0].limit).toBe(10_000_000)
  expect(u.windows[0].unit).toBe("tokens")
  expect(u.windows[0].span).toBe(24 * 3600)
  expect(u.windows[0].resetsAt).toBe(_internal.nextBeijingMidnight())
})

test("usage with no quota claimed says so, and a lapsed sign-in is marked", async () => {
  serve((call) => {
    if (call.url === BALANCE) return ok({ total_quota: 0 })
    throw new Error("unexpected " + call.url)
  })
  const hooks = await CodeArtsAuthPlugin({ client: {} })
  const u = await hooks.auth.usage(async () => stored())
  expect(u.balance).toBe("no free quota claimed")
  expect(u.windows).toBeUndefined()
  globalThis.fetch = async () => json({ error: "invalid_grant" }, 400)
  const gone = await hooks.auth.usage(async () => stored(Date.now() - 1000))
  expect(gone.signIn).toBe("expired")
  expect(gone.error).toContain("sign in again")
})

test("the config declares the provider, its API and the models it lists before sign-in", async () => {
  const hooks = await CodeArtsAuthPlugin({ client: {} })
  const config = { provider: {} }
  await hooks.config(config)
  const p = config.provider.codearts
  expect(p.name).toBe("CodeArts")
  expect(p.npm).toBe("@ai-sdk/openai-compatible")
  expect(p.api).toBe("https://snap-access.cn-north-4.myhuaweicloud.com/api/v2")
  expect(Object.keys(p.models)).toContain("openpangu-2.0-pro")
  expect(Object.keys(p.models)).toContain("glm-5.3-flash")
})

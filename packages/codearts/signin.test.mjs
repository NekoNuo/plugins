// Signing in as the IDE does: CodeArts' portal takes the browser and comes
// back to the callback on 127.0.0.1 (a 307 first, the code on the second
// call), whose code the STS trades for the account's credentials — bound
// to the DPoP key that stays with the sign-in, so every renewal signs with
// the same one. A renewal spends the refresh token and a new one comes
// back, which the plugin saves; one the STS no longer takes is the
// sign-in's end.
import "./nonet.mjs"
import { afterEach, expect, test } from "bun:test"
import { CodeArtsAuthPlugin, _internal } from "./index.mjs"

const real = globalThis.fetch
afterEach(() => (globalThis.fetch = real))

const STS = "https://sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens"
const jwk = await _internal.newDpopKey()

const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } })

function serve(handler) {
  const s = { calls: [], saves: [] }
  const real = globalThis.fetch
  globalThis.fetch = async (url, init = {}) => {
    const u = String(url)
    // the test's own calls to the sign-in's callback server go through
    if (u.startsWith("http://127.0.0.1")) return real(url, init)
    const call = { url: u, method: init.method ?? "GET", body: init.body, headers: new Headers(init.headers) }
    s.calls.push(call)
    return handler(call, s)
  }
  s.client = { auth: { set: async ({ body }) => s.saves.push(body) } }
  return s
}

// refreshJWT is a refresh token whose user_profile carries the identity,
// as the STS sends one.
function refreshJWT(profile) {
  const userProfile = "x." + Buffer.from(JSON.stringify(profile)).toString("base64url") + ".y"
  return "header." + Buffer.from(JSON.stringify({ user_profile: userProfile })).toString("base64url") + ".sig"
}

const creds = (n) => ({ access_key_id: "AK-" + n, secret_access_key: "SK-" + n, security_token: "ST-" + n, expiration: "2026-10-09T14:34:56Z" })

// stored is a kept sign-in with credentials that end when expires says.
const stored = (expires) =>
  _internal.toAuth(
    { v: 1, clientId: "codearts-agent", codeVerifier: "verifier-1", dpop: jwk, refreshToken: "r-1", userId: "u-1", userName: "Ann" },
    { accessKeyId: "AK-1", secretAccessKey: "SK-1", securityToken: "ST-1", expiration: new Date(expires).toISOString() },
  )

async function start() {
  const hooks = await CodeArtsAuthPlugin({ client: {} })
  const [method] = hooks.auth.methods
  expect(method.type).toBe("oauth")
  const a = await method.authorize()
  expect(a.method).toBe("auto")
  const u = new URL(a.url)
  expect(u.origin + u.pathname).toBe("https://codearts.huaweicloud.com/portal/authorize")
  const q = u.searchParams
  expect(q.get("client_id")).toBe("codearts-agent")
  expect(q.get("uri_scheme")).toBe("codearts-agent")
  expect(q.get("code_challenge_method")).toBe("SHA-256")
  expect(q.get("plugin-name")).toBe("snap_AIIDE")
  expect(q.get("theme")).toBe("2")
  return { a, q, port: Number(q.get("port")) }
}

test("the code the callback carries is traded for the account's credentials", async () => {
  const s = serve((call) => {
    expect(call.url).toBe(STS)
    expect(call.method).toBe("POST")
    expect(call.headers.get("dpop")).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/)
    return json({ credentials: creds(1), refresh_token: refreshJWT({ principal_id: "u-1", account_name: "Ann", account_id: "d-1" }) })
  })
  const { a, q, port } = await start()
  const res = await fetch(`http://127.0.0.1:${port}/oauth/callback?code=the-code`)
  expect(res.status).toBe(200)
  expect(await res.text()).toContain("signed in")
  const got = await a.callback()
  expect(got.type).toBe("success")
  expect(JSON.parse(got.access)).toEqual({ accessKeyId: "AK-1", secretAccessKey: "SK-1", securityToken: "ST-1", expiration: "2026-10-09T14:34:56Z" })
  const refresh = JSON.parse(got.refresh)
  expect(refresh.refreshToken).toBeTruthy()
  expect(refresh.dpop.d).toBeTruthy()
  expect(got.expires).toBe(Date.parse("2026-10-09T14:34:56Z"))
  expect(got.accountId).toBe("u-1")
  const form = new URLSearchParams(s.calls[0].body)
  expect(form.get("grant_type")).toBe("authorization_code")
  expect(form.get("code")).toBe("the-code")
  expect(form.get("code_verifier")).toBe(refresh.codeVerifier)
  expect(form.get("redirect_uri")).toBe(`http://127.0.0.1:${port}/oauth/callback`)
  expect(Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(refresh.codeVerifier))).toString("base64url")).toBe(q.get("code_challenge"))
})

test("the portal's first call back is handed on with a 307, and a code it turns away fails with why", async () => {
  const s = serve(() => json({ error: "invalid_grant", error_description: "the code has expired" }, 400))
  const { a, port } = await start()
  const hop = await fetch(`http://127.0.0.1:${port}/oauth/callback?secret=x&redirect=https://codearts.huaweicloud.com/portal/next`, { redirect: "manual" })
  expect(hop.status).toBe(307)
  expect(hop.headers.get("location")).toBe("https://codearts.huaweicloud.com/portal/next")
  const res = await fetch(`http://127.0.0.1:${port}/oauth/callback?code=old`)
  expect(await res.text()).toContain("the code has expired")
  const got = await a.callback()
  expect(got.type).toBe("failed")
  expect(got.error).toContain("400")
  expect(s.calls.length).toBe(1)
})

test("auth.refresh spends the refresh token and gives back the new one", async () => {
  const s = serve((call) => {
    expect(call.url).toBe(STS)
    return json({ credentials: creds(2), refresh_token: "r-2" })
  })
  const hooks = await CodeArtsAuthPlugin({ client: s.client })
  const got = await hooks.auth.refresh(stored(Date.now() - 60_000))
  const refresh = JSON.parse(got.refresh)
  expect(refresh.refreshToken).toBe("r-2")
  expect(refresh.userId).toBe("u-1")
  expect(JSON.parse(got.access).accessKeyId).toBe("AK-2")
  expect(got.expires).toBe(Date.parse("2026-10-09T14:34:56Z"))
  const form = new URLSearchParams(s.calls[0].body)
  expect(form.get("grant_type")).toBe("refresh_token")
  expect(form.get("refresh_token")).toBe("r-1")
  expect(form.get("code_verifier")).toBe("verifier-1")
  expect(form.get("client_id")).toBe("codearts-agent")
})

test("a refresh token the STS no longer takes is the sign-in's end", async () => {
  serve(() => json({ error: "invalid_grant", error_description: "the refresh token was spent" }, 400))
  const hooks = await CodeArtsAuthPlugin({ client: {} })
  let threw
  try {
    await hooks.auth.refresh(stored(Date.now() - 60_000))
  } catch (e) {
    threw = e
  }
  expect(threw?.signIn).toBe("expired")
  expect(threw?.message).toContain("sign in again")
})

test("a sign-in that isn't an oauth entry has nothing to renew", async () => {
  const hooks = await CodeArtsAuthPlugin({ client: {} })
  expect(await hooks.auth.refresh({ type: "api", key: "k" })).toBeUndefined()
})

test("the pasted callback's code is traded too, for a browser that can't reach this machine", async () => {
  const s = serve(() => json({ credentials: creds(3), refresh_token: "r-3" }))
  const hooks = await CodeArtsAuthPlugin({ client: s.client })
  const [, paste] = hooks.auth.methods
  expect(paste.type).toBe("oauth")
  const a = await paste.authorize()
  expect(a.method).toBe("code")
  const port = Number(new URL(a.url).searchParams.get("port"))
  expect(port).toBeGreaterThan(0)
  const wrong = await a.callback("nothing here")
  expect(wrong.type).toBe("failed")
  expect(wrong.error).toContain("no code")
  const got = await a.callback(`http://127.0.0.1:${port}/oauth/callback?code=pasted-code&state=x`)
  expect(got.type).toBe("success")
  expect(JSON.parse(got.access).accessKeyId).toBe("AK-3")
  const form = new URLSearchParams(s.calls[0].body)
  expect(form.get("code")).toBe("pasted-code")
  expect(form.get("redirect_uri")).toBe(`http://127.0.0.1:${port}/oauth/callback`)
  // the code alone is taken as it is
  expect(_internal.codeIn("a-plain-code")).toBe("a-plain-code")
  expect(_internal.codeIn(" https://x/cb?code=a%2Fb ")).toBe("a/b")
  expect(_internal.codeIn("")).toBe("")
})

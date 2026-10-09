// The signatures CodeArts takes are Huawei's SDK-HMAC-SHA256, computed the
// way the IDE and codearts2api compute them: every header name lowercased
// and sorted, the URI with a trailing slash, the query sorted and quoted
// like Python's quote(safe="-_.~"), the body's SHA-256. The expectations
// here are codearts2api's own server.py run at a fixed clock
// (2026-10-09T12:34:56Z) with the credentials AKIDEXAMPLE / SKEXAMPLE /
// STEXAMPLE; the DPoP proof and the PKCE pair are checked against the
// curve and the hash rather than a fixture, being different every time.
import "./nonet.mjs"
import { expect, test } from "bun:test"
import { _internal } from "./index.mjs"

const CREDS = { accessKeyId: "AKIDEXAMPLE", secretAccessKey: "SKEXAMPLE", securityToken: "STEXAMPLE" }
const DATE = "20261009T123456Z"
const CHAT = "https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions"
const BENEFIT = { maas_type: "benefit", "model-id": "glm-5.3-flash", "model-name": "glm-5.3-flash" }
const P256_N = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")

test("a free model's chat is signed with maas_type/model-id/model-name", () => {
  const body = '{"model":"glm-5.3-flash","messages":[{"role":"user","content":"hi"}],"stream":false}'
  const h = _internal.sdkHeaders(CREDS, "POST", CHAT, body, BENEFIT, DATE)
  expect(h.Authorization).toBe(
    "SDK-HMAC-SHA256 Access=AKIDEXAMPLE, SignedHeaders=content-type;host;maas_type;model-id;model-name;x-sdk-date;x-security-token, Signature=675e28cafa798d3902983a3c47f9e7ae99186d47775e80af791b368d82a0e907",
  )
  expect(h.host).toBe("snap-access.cn-north-4.myhuaweicloud.com")
  expect(h["x-sdk-date"]).toBe(DATE)
  expect(h["x-security-token"]).toBe("STEXAMPLE")
})

test("a plan model's chat is signed without them", () => {
  const body = '{"model":"openpangu-2.0-pro","messages":[{"role":"user","content":"hi"}],"stream":false}'
  const h = _internal.sdkHeaders(CREDS, "POST", CHAT, body, {}, DATE)
  expect(h.Authorization).toBe(
    "SDK-HMAC-SHA256 Access=AKIDEXAMPLE, SignedHeaders=content-type;host;x-sdk-date;x-security-token, Signature=1a4679579b71d3128d5f111d4c8be5ca87e67354b40638a119fad311bfa647ae",
  )
})

test("the agent list's GET is signed with its query and its headers", () => {
  const h = _internal.sdkHeaders(
    CREDS,
    "GET",
    "https://snap-access.cn-north-4.myhuaweicloud.com/v1/agent-center/agents/useragents?offset=0&limit=100",
    "",
    { "agent-type": "AgentCenter", "x-language": "zh-cn", accept: "application/json" },
    DATE,
  )
  expect(h.Authorization).toBe(
    "SDK-HMAC-SHA256 Access=AKIDEXAMPLE, SignedHeaders=accept;agent-type;content-type;host;x-language;x-sdk-date;x-security-token, Signature=2be9857247188daef923f97c531bed8e078c4b5484c801d600a406c685f5353f",
  )
})

test("an agent id's slashes are quoted the way Python's quote quotes them", () => {
  expect(_internal.canonicalQuery("?agent_id=abc%2F123")).toBe("agent_id=abc%2F123")
  const h = _internal.sdkHeaders(CREDS, "GET", "https://snap-access.cn-north-4.myhuaweicloud.com/v1/agent-center/agents/detail?agent_id=abc%2F123", "", {}, DATE)
  expect(h.Authorization).toBe(
    "SDK-HMAC-SHA256 Access=AKIDEXAMPLE, SignedHeaders=content-type;host;x-sdk-date;x-security-token, Signature=f28f898de9fee6d20324eb6de29006fbac834dc8ab4cfa8369381193622ef764",
  )
})

test("opengw's pages are signed the same way", () => {
  const sign = (method, path) => _internal.sdkHeaders(CREDS, method, "https://opengw.developer.huaweicloud.com" + path, "", {}, DATE).Authorization
  expect(sign("GET", "/api/v1/gateway/config")).toBe(
    "SDK-HMAC-SHA256 Access=AKIDEXAMPLE, SignedHeaders=content-type;host;x-sdk-date;x-security-token, Signature=1157ec3380f008d22b2cd5f9684dcd7c7a641819b1bf9d7b89d01d9d78675666",
  )
  expect(sign("GET", "/api/v1/benefit/claim")).toBe(
    "SDK-HMAC-SHA256 Access=AKIDEXAMPLE, SignedHeaders=content-type;host;x-sdk-date;x-security-token, Signature=85aa32ad916c38d397d50d2f1ea817bf12d3db55c12396fd0d90f36e5bdcf06e",
  )
  expect(sign("POST", "/api/v1/benefit/claim")).toBe(
    "SDK-HMAC-SHA256 Access=AKIDEXAMPLE, SignedHeaders=content-type;host;x-sdk-date;x-security-token, Signature=ae72bb181adf3afbdafb6d3de1ada277df5f31ecab07455406e66ddebe334467",
  )
})

test("the DPoP proof is an ES256 JWT over htm/htu with the key's public half, its S the lower one", async () => {
  const jwk = await _internal.newDpopKey()
  const at = Date.parse("2026-10-09T12:34:56Z")
  const proof = await _internal.dpopProof(jwk, "https://sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens", at)
  const [head, payload, sig] = proof.split(".")
  expect(JSON.parse(Buffer.from(head, "base64url").toString())).toEqual({
    alg: "ES256",
    typ: "dpop+jwt",
    jwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
  })
  const p = JSON.parse(Buffer.from(payload, "base64url").toString())
  expect(p.htm).toBe("POST")
  expect(p.htu).toBe("https://sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens")
  expect(p.iat).toBe(Math.floor(at / 1000))
  expect(p.jti).toMatch(/^[0-9a-f]{32}$/)
  const raw = Buffer.from(sig, "base64url")
  expect(raw.length).toBe(64)
  const s = BigInt("0x" + raw.subarray(32).toString("hex"))
  expect(s <= P256_N >> 1n).toBe(true)
  const key = await crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"])
  expect(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, raw, new TextEncoder().encode(head + "." + payload))).toBe(true)
})

test("the PKCE pair is the verifier and its SHA-256, and the identity comes out of the refresh token", async () => {
  const { verifier, challenge } = _internal.pkce()
  expect(verifier).toMatch(/^[A-Za-z0-9_-]{86}$/)
  expect(challenge).toBe(Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url"))
  const profile = Buffer.from(JSON.stringify({ principal_id: "u-9", account_name: "Ann", account_id: "d-9" })).toString("base64url")
  const token = "header." + Buffer.from(JSON.stringify({ user_profile: "x." + profile + ".y" })).toString("base64url") + ".sig"
  expect(_internal.userFromRefreshToken(token)).toEqual({ userId: "u-9", userName: "Ann", domainId: "d-9" })
  expect(_internal.userFromRefreshToken("nonsense")).toEqual({})
})

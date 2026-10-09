// Imported first by every test here: nothing a test runs reaches CodeArts.
// fetch goes to this machine (a test's fake, or the sign-in's own callback
// server on 127.0.0.1) or fails, so a test left without its fake can't
// send a token to sts.cn-north-4 or any other of CodeArts' hosts.
const local = (u) => /^https?:\/\/(127\.0\.0\.1|localhost|\[::1\])(:\d+)?(\/|$)/.test(u)
const realFetch = globalThis.fetch
globalThis.fetch = async (input, init) => {
  const u = typeof input === "string" ? input : input instanceof URL ? input.href : input.url
  if (!local(u)) throw new Error("a test asked " + u + " with no fake in place")
  return realFetch(input, init)
}

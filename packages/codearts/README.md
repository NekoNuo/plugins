# @magpie-community/opencode-codearts-auth

Signs in to Huawei Cloud CodeArts (华为云 CodeArts) with a Huawei Cloud
account and makes its models' requests, in OpenCode and in magpie.
Provider id: `codearts`.

## Signing in

- **Huawei Cloud account (browser)**: the CodeArts IDE's own sign-in.
  CodeArts' portal page takes the browser and comes back to a callback on
  `127.0.0.1` with a code, which is traded at
  `sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens` for the account's
  credentials: an access key, a secret key and a session token, about two
  hours' worth, and a refresh token that renews them for 28 days.
  - The trade is bound to a DPoP key (ES256) made at sign-in, which is kept
    with the sign-in: every renewal must sign with the same one.
  - The refresh token is spent by each renewal and a new one comes back;
    the plugin saves what came back.
- **Huawei Cloud account (paste the callback URL)**: the same sign-in for a
  browser that can't reach magpie's callback (magpie on a server). The page
  the browser ends on carries the code in its address; paste the address
  (or the code alone) into magpie to finish.

The sign-in is kept where OpenCode keeps sign-ins (`auth.json`; in magpie,
`plugin-auth.json`) as an `oauth` entry, holding the credentials, the
refresh token, the PKCE verifier and the DPoP key.

Refreshing:

- magpie renews 10 minutes before the credentials end, through
  `auth.refresh`, once per account, before its requests, models and usage
  need it. The new refresh token is saved.
- OpenCode doesn't call that hook: there the credentials are renewed before
  a request, and saved.
- A request CodeArts turns away (401 or 403) is renewed and sent once more.
- A refresh token the STS no longer takes marks the account: sign in again.

## Requests

CodeArts serves no OpenAI-compatible endpoint that takes a bearer key:
every request is signed with Huawei's SDK-HMAC-SHA256 (`x-sdk-date`,
`x-security-token` and an `Authorization: SDK-HMAC-SHA256 Access=…`
header), which the plugin's `fetch` does. Chats go to
`snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions`, the
endpoint the IDE uses, streaming and tool calls included.

The account's models come from two channels, told apart by their signature:

- **The plan's** (AgentCenter): the models the account's agents list.
- **The free quota's** (opengw.developer.huaweicloud.com): models served
  only after the day's claim, and only when asked with `maas_type: benefit`
  and the `model-id`/`model-name` headers signed in as well.

## Models

The `config` hook declares the models CodeArts lists before sign-in
(`openpangu-2.0-pro`, `openpangu-2.0-flash`, `GLM-5.2`, `glm-5.3-flash`,
`deepseek-v4-pro-0813`, `deepseek-v4-flash-0731`, `deepseek-v4.1-flash`).
Once signed in, the `provider.models` hook replaces them with the account's
own list, context windows included.

## Check-in and usage

- The free models are only served once the day's allowance (10,000,000
  tokens) is claimed. `auth.checkin` presses it, so magpie's Daily check-in
  switch for CodeArts keeps it in; a model list sync claims it too
  (idempotent), as the CodeArts IDE does — unclaimed, the free models
  answer `benefit not found`.
- `auth.usage` shows the free quota's balance as a day's window, resetting
  at Beijing midnight.

## Not included

- Reading the sign-in the CodeArts IDE keeps in its own state database (and
  writing a renewal back there). Sign in here instead.
- Switching between several accounts. OpenCode keeps one sign-in per
  provider; magpie keeps one per account signed in.
- The IDE's other agents, plugins and web tools.

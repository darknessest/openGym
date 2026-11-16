# Cloudflare deployment

The examples use `https://opengym.example.com`; substitute your own hostname.

openGym runs using Workers Static Assets, a SQLite-backed
Durable Object for accounts and profile documents, R2 for private uploads, and durable alarms
for media cleanup and rest notifications. There is no continuously running server or model
runtime. MCP connects an assistant on your computer; the optional embedded AI Coach can also
run through HTTPS providers or the owner's ChatGPT plan. Both use the same training profile.

## Set up the embedded Coach

Open **Settings → Admin dashboard → AI Coach**, then enable the Coach. Choose an Anthropic
API key or another HTTPS provider, or select **ChatGPT plan** for the instance owner's plan.
Each profile chooses whether to consent to Coach use. Proposals are reviewed/applied in the app;
the server does not silently rewrite training plans. Per-profile and instance daily limits apply.
Changing provider or endpoint host pauses automatic reviews for every profile. Re-enable them
in Coach's **Automatic reviews** settings after approving the new destination.

### ChatGPT sign-in from your computer

OpenAI requires a callback on the computer running your browser, at
`http://127.0.0.1:PORT/auth/callback`. The website's public domain is not an allowed replacement.
openGym's helper starts that listener before authorization and returns your browser to the
hosted app automatically. There is no callback URL to copy manually.

1. On your computer, install Node 22 or newer and download **ChatGPT login helper** from the
   Coach setup card. The helper is also in this repository at `frontend/public/chatgpt-login.mjs`.
2. Run it on that computer, not on your Cloudflare server:

   ```sh
   node frontend/public/chatgpt-login.mjs https://opengym.example.com
   ```

   For the downloaded file, use its local path instead of `frontend/public/chatgpt-login.mjs`.
3. The helper opens openGym in your browser, or prints the address to open. Sign in as the
   instance owner, open Coach setup, and choose **Continue with ChatGPT**.
4. Approve ChatGPT plan use. OpenAI returns to the helper, which sends the browser back to
   openGym to complete the connection. The helper then stops.

The helper listens only on `127.0.0.1`, chooses an available port, validates a one-use relay
nonce, and expires after 15 minutes. It exchanges no tokens and writes no credentials. PKCE,
OIDC identity/nonce checks and credential encryption happen on the server. Callback data travels
back in a URL fragment, is removed before login/router boot, and is submitted through the
owner's authenticated session. A missing/expired/replaced session requires a fresh attempt.
The exact callback URI is retained for authorization and code exchange, as required by
[OpenAI's sign-in protocol](https://developers.openai.com/siwc/token-sharing-open-source/sign-in).

The owner previously confirmed eligibility for this hosted ChatGPT integration. Live sign-in
still requires that owner's ChatGPT account and approval. Claude is available via an Anthropic
API key; a Claude subscription is used through MCP in Claude rather than imported into Coach.

## Connect your local assistant

1. Sign in to [openGym](https://opengym.example.com).
2. Open **Settings → MCP → New token**. Name it for the client, for example **My computer**.
3. Give **Plans & routines → Change directly** if you want it to create/edit routines, and
   **Workouts → See** if you want it to review training. Other categories are optional. Choose
   the expiry you want. Each token reaches only its own profile and the categories you selected.
4. Copy the token once, then configure your local MCP client with:

   - URL: `https://opengym.example.com/mcp`
   - Transport: Streamable HTTP
   - Header: `Authorization: Bearer YOUR_TOKEN`

MCP itself does not need ChatGPT or Claude credentials in openGym. Your local assistant handles
its model access through its own account; its openGym token is separate from Coach credentials.

### Claude Code

Put the token in your local environment as `OPENGYM_TOKEN` without adding its value to shell
history, then run:

```sh
claude mcp add --scope user --transport http opengym https://opengym.example.com/mcp \
  --header "Authorization: Bearer $OPENGYM_TOKEN"
```

The user scope keeps the credential in your personal Claude configuration rather than a
project's checked-in MCP configuration. Open Claude Code and use `/mcp` to check the connection.
The command uses a fixed bearer token; no browser OAuth callback is needed.
See [Claude Code's MCP guide](https://code.claude.com/docs/en/mcp).

### Claude Desktop

1. Open **Customize → Connectors → Add → Custom → Web**. Depending on the app version, the
   button may instead say **Add custom connector**.
2. Name it **openGym** and enter `https://opengym.example.com/mcp`.
3. Choose **No sign in** for authentication, since this server uses a fixed token rather than
   OAuth. Under **Request headers**, add `Authorization` with the value `Bearer YOUR_TOKEN`.
4. Add the connector and enable it for the conversation where you want to use your training.

Claude Desktop's remote connector sends requests from Anthropic's cloud. The endpoint is
public HTTPS, while the token restricts access to your selected profile/categories. These
[connector and request-header settings](https://support.claude.com/en/articles/11176164-use-connectors-to-extend-claude-s-capabilities)
are documented by Anthropic. They do not require a ChatGPT/Claude credential inside openGym.

For a connection launched locally by Desktop, the existing stdio bridge can run on your
computer with `OPENGYM_URL=https://opengym.example.com`, `OPENGYM_SOURCE=api`, and
`OPENGYM_TOKEN`; see [mcp/README.md](../mcp/README.md). It uses the same scoped API and has
no need for a local data folder.

Try asking: “Review my recent training and suggest a three-day plan.” The tools support
exercise search, routines, weekly plans, workouts, body weight, strength estimates and muscle
balance. Writes offer previews; routine updates and deletion check the revision you read.
A saved routine syncs to your phone through the same profile sync as an edit in the app.

Revoke a client in **Settings → MCP**, or use **Sign out everywhere** to revoke all sessions
and tokens for that profile. Full phone/browser session tokens are refused at MCP. API tokens
cannot administer accounts, read other profiles, access private uploads, or call account routes.
Only token hashes are stored. Requests check token validity afresh.

This endpoint uses token authentication for local clients. Hosted connector OAuth, dynamic
client registration, and subscription imports are not provided. The general upstream
[MCP over HTTPS guide](MCP_REMOTE.md) documents the separate Docker deployment's OAuth features.

## First use and phone authentication

The first profile redeems the private owner invite in `cloudflare/.owner-invite`, using a passkey
or password. It becomes the owner/admin. Subsequent profiles need an invite from the admin
page at `/#/admin`. Passkeys are bound to `opengym.example.com`.

The phone uses the existing revocable device session:

1. Sign in to the HTTPS website in the phone's browser.
2. **Settings → Account → Pair the mobile app**, then confirm your password/passkey.
3. In the app choose **Connect to my server**, enter the HTTPS address, and redeem the
   five-minute single-use pairing code.

No second device or Cloudflare Access is needed. If Access is added later, preserve the gym's
Authorization bearer header and use the app's separate CF-Access service headers. OPTIONS
must reach the Worker. Access service credentials admit the device; the gym session identifies
the person. An MCP token is a separate, narrower credential.

## Flood protection and HTTPS

Cloudflare provides [network and HTTP DDoS protection](https://developers.cloudflare.com/ddos-protection/).
The Worker also applies native admission limits before database access: about 300 API/MCP
requests per minute per IP and 30 login, signup, device-link and pairing attempts per minute.
Counters are approximate and per Cloudflare location. Rejected requests return HTTP 429 with
Retry-After and native CORS headers. Per-token request and profile write limits apply as well.
Static assets and preflights do not use these counters.

The Worker still starts to check requests; these limits are not spending caps. Account-wide
[spending limits and alerts](https://developers.cloudflare.com/billing/manage/spend-management/)
need deliberate thresholds because other applications share the account. Deployment does not
change billing settings.

Use the HTTPS URL. Plain HTTP is also served until a host-scoped Cloudflare Redirect Rule is
configured for `opengym.example.com`, preserving path/query while redirecting to HTTPS.
The deployment token receives HTTP 403 when accessing the zone's redirect rules, so deployment
has not configured this zone-level rule.

## Deploy and develop

Use Node 22 or newer. From `cloudflare/`:

For a new instance, copy `wrangler.example.jsonc` to the Git-ignored `wrangler.jsonc`, then set the custom domain, `ORIGIN`,
`RP_ID`, and your Worker/R2 names. Keep an existing instance's names stable when updating it.

```sh
# First setup only: -n preserves an existing deployment configuration.
cp -n wrangler.example.jsonc wrangler.jsonc
# For a new instance, edit wrangler.jsonc for your hostname and account.
npm ci --ignore-scripts
npx wrangler whoami
# Once for a new instance:
npx wrangler r2 bucket create opengym-personal-media
npx wrangler secret put SESSION_SECRET
npx wrangler secret put SETUP_CODE
bash deploy.sh
```

The build installs MCP and frontend dependencies, builds the app, and stages the licensed
exercise media. Wrangler manages the custom domain and HTTPS certificate. Ordinary redeploys
retain the Worker name, Gym/PushTimers namespaces, secrets and R2 bucket; changing their names
creates different storage. The session secret must remain stable.

Keep deployment hostnames in the Git-ignored `cloudflare/wrangler.jsonc`.
The personal deployment keeps its private values in the Git-ignored, owner-readable
`cloudflare/.production-secrets.json`. The owner invite alone is in `.owner-invite`.
Never commit these files or put their contents into a local MCP configuration.

For local development, install dependencies in `mcp/` and `cloudflare/`, build the frontend,
copy `.dev.vars.example` to `.dev.vars`, and set independent disposable secrets. Add
`ORIGIN="http://localhost:8787"` and `RP_ID="localhost"`, then run `npm run dev` in
`cloudflare/`. Keep verification profiles/storage separate from production.

Profile JSON writes are capped at 5 MiB. Private media has per-profile quotas and type/size
limits reported by `/api/config`. Account deletion cleans up tokens and queues durable R2
cleanup. Ordinary unreferenced media has a 14-day grace period; explicit reset releases it
immediately. Export profile data and back up R2 media regularly. Use Durable Object SQLite
recovery for operational recovery. Do not delete namespaces or the bucket during redeployment.

## Verification and review

The original serverless rebuild was verified through actual Workers HTTP/SQLite/R2 and browser
flows, including passkeys, phone/watch pairing, sync conflicts, media cleanup and rest timers.
It received four bounded Sol 6.1 xhigh review rounds. The fourth covered admission throttling;
its final device-link limit fix passed HTTP verification without another review.

The MCP replacement is a separate change. Disposable local verification passed through the
real Wrangler runtime with SQLite and the official MCP SDK client:

- Initialization, tool discovery, catalogue search, routine previews without writes, and
  routine creation/update through the MCP endpoint.
- The created routine appearing through a newly paired phone's normal data endpoint; stale
  routine revisions refusing to overwrite another write.
- Scoped tool visibility, refusal of direct writes with read-only tokens, and private fields
  excluded from read/conflict documents.
- Token revocation, global logout, separate profiles' data/token isolation, and token invalidation
  after profile deletion.
- Settings → MCP reaching token setup, the frontend build, and the deployment bundle
  (approximately 748 KiB compressed).

These probes made no model calls and used no production profile data. No new committed tests
were added.

The MCP replacement received one Sol 6.1 xhigh review round. It found that the shared JSON
reader ignored MCP's smaller body limit. The reader now accepts a per-call limit, retaining
the ordinary API's 5 MiB default. The fix was verified through HTTP, without another review
round. No other actionable findings were reported.

The preceding MCP-only deployment passed production checks on 2026-11-16: MCP health and
Bearer authentication challenge, token-auth configuration, native preflight, and frontend
build integrity. Its old Coach documents were removed; restoring Coach now starts disconnected
and requires a fresh provider connection. Production training documents were not used for tests.

The restoration was verified with the real Node helper, browser, Workers/SQLite runtime, and
controlled responses at the OpenAI network boundary. The browser completed the helper's
127.0.0.1 callback, returned to hosted Admin, removed callback data from its address, and showed
ChatGPT connected. The fixture checked PKCE, exact redirect URI, ID-token signature/nonce,
and plan-use permission. Opening the helper link in an existing app tab also completed sign-in.
Invalid helper requests were rejected without closing the listener;
a successful handoff closed it. Further HTTP checks passed one-use callbacks, exact-session
and port binding, returning-account identity checks, preserved credentials after a rejected
account switch, durable Coach test execution, MCP scope limits, and logout revocation. Wrong
state/port callbacks leave the valid attempt usable; concurrent valid completions exchange
only once. The ordinary frontend build includes the exact helper as a public asset.
Two-session HTTP checks also confirmed that logging out another session preserves active
Coach tests/training jobs, while logging out the initiating session cancels its own jobs.

These checks made no live model requests. Live ChatGPT approval and inference still require
the owner's account.

Restoration review uses Sol 6.1 with extra-high reasoning:

- Round 1 found that unrelated callbacks could consume a pending attempt and ordinary web
  builds omitted the helper. Callback validation now precedes the synchronous claim, and the
  helper lives in Vite's shared public assets. HTTP race/rejection checks and build artifact
  equality passed after those fixes.
- Round 2 found that a single-session logout cleared another session's Coach status. Cleanup
  now clears only status for jobs cancelled by that logout; completed profile proposals remain
  until resolved or globally revoked. Two-session job execution/cancellation checks passed.
- Round 3 found that a provider/destination change retained scheduled-review permission.
  Configuration changes now pause existing cadences through the normal atomic sync commit,
  with a new revision and edit stamp. HTTP checks confirmed provider/host changes pause reviews,
  stale writes receive conflicts, workout sync sends nothing while paused, model-only edits
  retain schedules, and explicitly re-enabling a schedule resumes provider execution.

All three review rounds are complete. The final privacy fix passed those integration checks;
it did not receive another independent review. No new committed tests were added.

The restored deployment passed production checks on 2026-11-16: Coach capability and
authentication admission, MCP health/Bearer challenge, native-app preflight including optional
Access headers, and exact helper/frontend artifact bytes. Existing profile documents and MCP
tokens were preserved. Real provider authorization remains an owner action.

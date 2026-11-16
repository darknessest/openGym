# Cloudflare deployment

The examples use `https://opengym.example.com`; substitute your own hostname.

openGym runs using Workers Static Assets, a SQLite-backed
Durable Object for accounts and profile documents, R2 for private uploads, and durable alarms
for media cleanup and rest notifications. There is no continuously running server or model
runtime. The embedded AI Coach and its scheduled reviews have been removed from this deployment.
Training happens in openGym; an assistant on your computer uses MCP when you ask it to.

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

No ChatGPT or Claude credentials are uploaded to openGym. Your local assistant handles model
access through its own account. openGym only serves tools and stores the changes you request.

For **Codex CLI**, put the token in the local environment as `OPENGYM_TOKEN` without adding it
to shell history, then run:

```sh
codex mcp add opengym --url https://opengym.example.com/mcp --bearer-token-env-var OPENGYM_TOKEN
```

Its equivalent configuration in `~/.codex/config.toml` is:

```toml
[mcp_servers.opengym]
url = "https://opengym.example.com/mcp"
bearer_token_env_var = "OPENGYM_TOKEN"
```

Start Codex with that environment variable available. A client that accepts JSON MCP
configuration can use the example shown on the MCP page; each client's config format differs.
The existing local stdio bridge can also run on your computer with `OPENGYM_URL` and
`OPENGYM_TOKEN`; see [mcp/README.md](../mcp/README.md).

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

Production checks passed on 2026-11-16: MCP health and Bearer authentication challenge,
token-auth configuration, removed Coach endpoints, native preflight, and the published frontend
matching the verified build. The prior Coach configuration/credential/job documents were
removed from server storage. Production training documents were not used for verification.

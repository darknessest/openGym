import * as oauth from '../api/oauth.js';
import { createToken, findToken, revokeTokens, ScopeError } from '../api/tokens.js';
import { json, readJson, readText, HttpError } from './http.js';
import { scheduleAlarm } from './alarms.js';

export const OAUTH_PUBLIC_POSTS = new Set([
  '/api/oauth/register', '/api/oauth/token', '/api/oauth/revoke',
]);
const SESSION_ROUTES = new Set([
  'GET /api/oauth/request', 'POST /api/oauth/approve', 'POST /api/oauth/deny',
]);
const DISCOVERY = new Set([
  '/.well-known/oauth-authorization-server', '/.well-known/openid-configuration',
  '/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp',
]);
const TRANSIENT_MAX = 100;

export class OAuth {
  constructor(store, accounts, ctx) {
    this.store = store;
    this.accounts = accounts;
    this.ctx = ctx;
    this.issuer = accounts.origin;
  }

  state() {
    const data = this.store.get('oauth', { oauthClients: [], pending: [], codes: [] });
    const now = Date.now();
    return {
      ...data,
      oauthClients: data.oauthClients.filter(c => now - (c.used || c.created) < oauth.CLIENT_IDLE_MS),
      pending: new Map(data.pending.filter(([, r]) => now - r.at < oauth.REQUEST_TTL_MS)),
      codes: new Map(data.codes.filter(([, c]) => now - c.at < oauth.CODE_TTL_MS)),
    };
  }

  async prune() {
    const next = this.store.transaction(() => {
      const data = this.state();
      this.store.put('oauth', { oauthClients: data.oauthClients,
        pending: [...data.pending], codes: [...data.codes] });
      const deadlines = [...data.pending.values()].map(r => r.at + oauth.REQUEST_TTL_MS)
        .concat([...data.codes.values()].map(c => c.at + oauth.CODE_TTL_MS));
      return deadlines.length ? Math.min(...deadlines) : null;
    });
    if (next !== null) await scheduleAlarm(this.ctx, next);
  }

  async handle(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    const route = request.method + ' ' + path;
    if (request.method === 'GET' && DISCOVERY.has(path)) {
      return json(path.startsWith('/.well-known/oauth-protected-resource')
        ? oauth.protectedResourceMetadata(this.issuer)
        // Dynamic registration avoids an outbound metadata fetch at this trust boundary.
        : { ...oauth.authServerMetadata(this.issuer), client_id_metadata_document_supported: false });
    }
    const publicPost = request.method === 'POST' && OAUTH_PUBLIC_POSTS.has(path);
    if (!publicPost && route !== 'GET /api/oauth/authorize' && !SESSION_ROUTES.has(route)) return null;
    try {
      if (url.search.length > 8192) throw new HttpError(414, 'request URL too long');
      const session = SESSION_ROUTES.has(route) ? await this.accounts.requestKey(request) : null;
      const before = session ? this.accounts.require(session) : null;
      if (session && request.method === 'POST') {
        const origin = request.headers.get('origin');
        if ((origin && origin !== this.issuer) || request.headers.get('sec-fetch-site') === 'cross-site') {
          throw new HttpError(403, 'request must come from this server');
        }
      }
      let body = null, form = null;
      if (request.method === 'POST') {
        if (path === '/api/oauth/token' || path === '/api/oauth/revoke') {
          const raw = await readText(request, 16384);
          if (/application\/json/i.test(request.headers.get('content-type') || '')) {
            let parsed;
            try { parsed = JSON.parse(raw); } catch { throw new HttpError(400, 'invalid JSON'); }
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new HttpError(400, 'JSON object required');
            form = new URLSearchParams(Object.entries(parsed));
          } else form = new URLSearchParams(raw);
          if (!form.get('client_id')) {
            const client = oauth.basicClientId(request.headers.get('authorization'));
            if (client) form.set('client_id', client);
          }
        } else body = await readJson(request, 16384);
      }
      const response = this.store.transaction(() => {
        const user = session ? this.accounts.require(session, before.id) : null;
        if (user && user.sv !== before.sv) throw new HttpError(401, 'not signed in');
        this.accounts.rate('oauth:' + (user?.id || request.headers.get('cf-connecting-ip') || 'unknown'), 30, 60000);
        const state = this.state();
        const users = this.store.get('users', []);
        const originals = new Map(users.map(u => [u.id, JSON.stringify(this.store.get('tokens:' + u.id, []))]));
        const db = { users, oauthClients: state.oauthClients,
          apiTokens: [...originals.values()].flatMap(value => JSON.parse(value)) };
        const ownerOf = id => users.find(u => u.id === id) || null;
        let result;
        if (route === 'POST /api/oauth/register') {
          // Do not let anonymous registration evict an active client's redirect registration.
          if (db.oauthClients.length >= oauth.CLIENTS_MAX) throw new HttpError(429, 'client registration limit reached');
          const r = oauth.registerClient(db, body);
          result = json(r.body, r.status);
        } else if (route === 'GET /api/oauth/authorize') {
          if (state.pending.size >= TRANSIENT_MAX) throw new HttpError(429, 'too many pending sign-ins');
          if (!url.searchParams.has('resource')) url.searchParams.set('resource', this.issuer + '/mcp');
          const r = oauth.startAuthorize(db, url.searchParams, state.pending, Date.now(), {
            issuer: this.issuer, resource: this.issuer + '/mcp',
          });
          const location = r.ok ? this.issuer + '/#/connect/' + r.request.id : r.redirect;
          result = location ? new Response(null, { status: 302, headers: { location, 'cache-control': 'no-store' } })
            : json({ error: r.error }, 400);
        } else if (route === 'GET /api/oauth/request') {
          const shown = oauth.describeRequest(state.pending, url.searchParams.get('id'));
          result = shown ? json(shown) : json({ error: 'this sign-in has expired', code: 'expired' }, 404);
        } else if (route === 'POST /api/oauth/approve') {
          if (state.codes.size >= TRANSIENT_MAX) throw new HttpError(429, 'too many pending codes');
          const r = oauth.approve(state.pending, state.codes, body.id, body, (name, scopes, days) => {
            const made = createToken(db, user, { name, scopes, days, evict: row => !!row.connector });
            return { row: made.row };
          });
          if (r.ok) this.accounts.audit('auth.token.create', user);
          result = r.ok ? json({ redirect: r.redirect }) : json({ error: r.error, code: 'expired' }, r.status);
        } else if (route === 'POST /api/oauth/deny') {
          const r = oauth.deny(state.pending, body.id);
          result = r.ok ? json({ redirect: r.redirect }) : json({ error: r.error, code: 'expired' }, r.status);
        } else if (route === 'POST /api/oauth/token') {
          if (form.get('grant_type') === 'refresh_token' &&
              form.get('resource') && form.get('resource') !== this.issuer + '/mcp') {
            return json({ error: 'invalid_target' }, 400);
          }
          if (form.get('grant_type') === 'refresh_token' && !form.get('client_id')) {
            return json({ error: 'invalid_client' }, 400);
          }
          const r = form.get('grant_type') === 'refresh_token'
            ? oauth.refresh(db, form, ownerOf) : oauth.exchange(state.codes, form, db);
          result = json(r.body, r.status, { pragma: 'no-cache' });
        } else {
          const row = oauth.revocable(db, form.get('token') || '', value => findToken(db, value, ownerOf));
          if (row && (!form.get('client_id') || form.get('client_id') === row.connector.client)) {
            revokeTokens(db, row.userId, row.id);
            this.accounts.audit('auth.token.revoke', ownerOf(row.userId));
          }
          result = json({});
        }
        // Persist even failed exchanges: a tried authorization code is single-use.
        this.store.put('oauth', { oauthClients: db.oauthClients,
          pending: [...state.pending], codes: [...state.codes] });
        for (const [id, original] of originals) {
          const tokens = db.apiTokens.filter(row => row.userId === id);
          if (JSON.stringify(tokens) !== original) this.store.put('tokens:' + id, tokens);
        }
        return result;
      });
      await this.prune();
      return response;
    } catch (error) {
      if (!(error instanceof HttpError) && !(error instanceof ScopeError)) throw error;
      return json({ error: error.message, ...(error.code ? { code: error.code } : {}) }, error.status,
        error.retryAfter ? { 'retry-after': String(error.retryAfter) } : {});
    }
  }
}

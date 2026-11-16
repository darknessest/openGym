import {
  createToken, findToken, touchToken, listTokens, revokeTokens, scopedState, mergeScoped,
  ScopeError, TOKEN_CATEGORIES, TOKEN_DAYS, DEFAULT_DAYS,
} from '../api/tokens.js';
import { commitState } from './state.js';
import { json, readJson, HttpError } from './http.js';

const SESSION_ROUTES = new Set(['GET /api/tokens', 'POST /api/tokens', 'POST /api/tokens/revoke']);
const TOKEN_ROUTES = new Set([
  'GET /api/token/me', 'GET /api/token/data', 'GET /api/token/data/rev', 'PUT /api/token/data',
]);

export class Tokens {
  constructor(store, accounts) {
    this.store = store;
    this.accounts = accounts;
  }

  // Authentication only: callers must repeat it after any await before using account data.
  authorize(request) {
    const authorization = request.headers.get('authorization') || '';
    const token = authorization.startsWith('Bearer ') ? authorization.slice(7).trim() : '';
    if (!/^ogt_[A-Za-z0-9_-]{43}$/.test(token)) {
      throw new HttpError(401, 'invalid or expired token', 'token-invalid');
    }
    let authenticated = null;
    // Tokens contain no account identifier. Scan only existing profiles' bounded token documents,
    // never arbitrary document rows or orphaned tokens belonging to a removed profile.
    for (const user of this.store.get('users', [])) {
      const db = { apiTokens: this.store.get('tokens:' + user.id, []) };
      const row = findToken(db, token, uid => uid === user.id ? user : null);
      if (row && !row.kind) authenticated = { user, row, db };
    }
    if (!authenticated) throw new HttpError(401, 'invalid or expired token', 'token-invalid');
    return authenticated;
  }

  async handle(request) {
    const url = new URL(request.url);
    const route = request.method + ' ' + url.pathname;
    if (!SESSION_ROUTES.has(route) && !TOKEN_ROUTES.has(route)) return null;
    try {
      if (SESSION_ROUTES.has(route)) {
        // Accounts deliberately recognizes only full cookie/device sessions, including when a
        // scoped bearer is presented alongside a valid cookie: no cookie fallback is allowed.
        const auth = await this.accounts.requestKey(request);
        const before = this.accounts.require(auth);
        const account = request.headers.get('x-opengym-account');
        if (account && account !== String(before.id)) {
          throw new HttpError(409, 'signed in as another account now', 'account-mismatch');
        }
        if (request.method !== 'GET' && !auth.bearer) {
          const origin = request.headers.get('origin');
          if ((origin && origin !== (this.accounts.origin || url.origin)) ||
              request.headers.get('sec-fetch-site') === 'cross-site') {
            throw new HttpError(403, 'request must come from this server', 'origin');
          }
        }
        this.accounts.rate('tokens:manage:' + before.id + ':' + request.method,
          request.method === 'GET' ? 120 : 20, request.method === 'GET' ? 60000 : 3600000);
        const body = request.method === 'GET' ? null : await readJson(request);
        return this.store.transaction(() => {
          const user = this.accounts.require(auth, before.id);
          if (user.sv !== before.sv) throw new HttpError(401, 'not signed in');
          const key = 'tokens:' + user.id;
          const db = { apiTokens: this.store.get(key, []) };
          if (route === 'GET /api/tokens') {
            return json({ tokens: listTokens(db, user), categories: TOKEN_CATEGORIES,
              days: TOKEN_DAYS, defaultDays: DEFAULT_DAYS, mcp: true });
          }
          if (route === 'POST /api/tokens') {
            const made = createToken(db, user, { name: body.name, scopes: body.scopes, days: body.days });
            this.store.put(key, db.apiTokens);
            this.accounts.audit('auth.token.create', user);
            return json({ token: made.token, id: made.row.id, tokens: listTokens(db, user) });
          }
          if (body.id != null && (typeof body.id !== 'string' || !body.id || body.id.length > 100)) {
            throw new HttpError(400, 'invalid token id');
          }
          const gone = revokeTokens(db, user.id, body.id ?? null);
          if (gone.length) {
            this.store.put(key, db.apiTokens);
            this.accounts.audit('auth.token.revoke', user);
          }
          return json({ ok: true, revoked: gone.length, tokens: listTokens(db, user) });
        });
      }

      const before = this.authorize(request);
      const write = request.method === 'PUT';
      // Charge before reading a body so malformed, forbidden and conflicting requests cannot
      // bypass the sustained budget. A profile cannot multiply its write budget with new tokens.
      this.accounts.rate(write ? 'tokens:write:' + before.user.id : 'tokens:read:' + before.user.id + ':' + before.row.id,
        write ? 20 : 120, write ? 3600000 : 60000);
      const body = write ? await readJson(request) : null;
      return this.store.transaction(() => {
        const { user, row, db } = this.authorize(request);
        if (user.id !== before.user.id || user.sv !== before.user.sv || row.id !== before.row.id) {
          throw new HttpError(401, 'invalid or expired token', 'token-invalid');
        }
        if (touchToken(row)) this.store.put('tokens:' + user.id, db.apiTokens);
        if (route === 'GET /api/token/me') {
          return json({ user: { id: user.id, name: user.name || '' },
            token: { id: row.id, name: row.name, scopes: { ...row.scopes }, exp: row.exp || null } });
        }
        const current = this.store.get('state:' + user.id);
        const rev = current?._rev || 0;
        const wid = current?._wid || null;
        if (route === 'GET /api/token/data/rev') return json({ rev, ...(wid ? { wid } : {}) });
        if (!write) return json({ state: current ? scopedState(current, row.scopes) : null, rev, ...(wid ? { wid } : {}) });
        if (!Number.isInteger(body.baseRev)) {
          throw new HttpError(400, 'baseRev required: write over the revision you read', 'base-rev');
        }
        if (!body.state || typeof body.state !== 'object' || Array.isArray(body.state)) {
          throw new HttpError(400, 'state required');
        }
        if (!current || body.baseRev !== rev || (body.baseWid ?? null) !== wid) {
          return json({ error: current ? 'conflict' : 'this profile has not synced from a device yet',
            ...(!current ? { code: 'not-synced' } : {}), rev, ...(wid ? { wid } : {}),
            state: current ? scopedState(current, row.scopes) : null }, 409);
        }
        const merged = mergeScoped(current, body.state, row.scopes);
        if (!merged.touched.length) return json({ ok: true, unchanged: true, rev, ...(wid ? { wid } : {}) });
        const done = commitState(this.store, user.id, current,
          { state: merged.next, baseRev: body.baseRev, baseWid: body.baseWid, stamped: false });
        // Keep a conflict from the common state writer scoped as well.
        if (done.status === 409 && done.body.state) {
          done.body.state = scopedState(done.body.state, row.scopes);
        }
        if (done.status === 200) this.accounts.audit('token.write', user);
        return json(done.body, done.status);
      });
    } catch (error) {
      if (!(error instanceof HttpError) && !(error instanceof ScopeError)) throw error;
      return json({ error: error.message, ...(error.code ? { code: error.code } : {}),
        ...(error.retryAfter ? { retryAfter: error.retryAfter } : {}) }, error.status,
      error.retryAfter ? { 'Retry-After': String(error.retryAfter) } : {});
    }
  }
}

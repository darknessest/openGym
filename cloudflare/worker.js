import { DurableObject } from 'cloudflare:workers';
import { Store } from './store.js';
import { Accounts } from './accounts.js';
import { stateRoutes } from './state.js';
import { Tokens } from './tokens.js';
import { mcpRequest } from './mcp.js';
import { mediaRoutes, mediaConfig, mediaCleanup, scheduleMedia } from './media.js';
import { Push } from './push.js';
import { Coach } from './coach.js';
import { HttpError, json } from './http.js';
import { excusedOn, nudgeFor } from '../api/nudge.js';
import { watchRoutes } from './watch.js';
import { scheduleAlarm } from './alarms.js';
export { PushTimers } from './push-timers.js';

export class Gym extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.store = new Store(ctx.storage);
    this.accounts = new Accounts(this.store, env);
    this.tokens = new Tokens(this.store, this.accounts);
    this.push = new Push(this.store, env, ctx);
    this.coach = new Coach(this.store, env, ctx, this.push);
  }

  async fetch(request) {
    try {
      if (!this.env.SESSION_SECRET || !this.env.SETUP_CODE) return json({ error: 'server secrets are not configured' }, 503);
      const path = new URL(request.url).pathname;
      const user = await this.accounts.user(request);
      if (path === '/api/health' && request.method === 'GET') return json({ ok: true, writable: true, runtime: 'cloudflare' });
      if (path === '/api/config' && request.method === 'GET') {
        return json({
          invite_only: this.env.INVITE_ONLY === 'true', allow_guest: false,
          password_login: this.env.PASSWORD_LOGIN === 'true', signed_in: !!user,
          media: mediaConfig, coach_supported: true, coach: this.coach.publicConfig(user), mcp_auth: 'token',
          ...(user ? { api_tokens: true, mcp: true } : {})
        });
      }
      for (const handler of [
        () => this.accounts.handle(request),
        () => stateRoutes(this.store, request, user),
        () => this.tokens.handle(request),
        () => mediaRoutes(this.store, this.env, request, user, this.ctx),
        () => watchRoutes(this.store, request, user),
        () => this.push.handle(request, user),
        () => this.coach.handle(request, user)
      ]) {
        const response = await handler();
        if (response) {
          if (request.method !== 'GET') {
            await scheduleMedia(this.store, this.ctx);
            await this.coach.wake();
          }
          return response;
        }
      }
      if (path === '/api/activity' && request.method === 'POST') {
        if (!user) throw new HttpError(401, 'not signed in');
        return json({ ok: true });
      }
      if (path === '/api/nudge-check' && request.method === 'GET') {
        if (!user) throw new HttpError(401, 'not signed in');
        const date = new URL(request.url).searchParams.get('date') || '';
        if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || Number.isNaN(Date.parse(date + 'T00:00:00Z'))) throw new HttpError(400, 'date must be YYYY-MM-DD', 'date-invalid');
        const state = this.store.get('state:' + user.id, {});
        const done = (state.workouts || []).some(w => w?.d === date) || excusedOn(state, date);
        return json({ date, done, nudge: !done && !!nudgeFor(state, date), rev: state._rev || 0 });
      }
      return json({ error: 'not found' }, 404);
    } catch (error) {
      if (error instanceof HttpError) return json({ error: error.message, ...(error.code ? { code: error.code } : {}) }, error.status);
      console.error('API request failed', error.name, error.message);
      return json({ error: 'server error' }, 500);
    }
  }

  async alarm() {
    const results = await Promise.allSettled([
      mediaCleanup(this.store, this.env, this.ctx),
      this.coach.alarm()
    ]);
    const failed = results.find(result => result.status === 'rejected');
    if (failed) {
      await scheduleAlarm(this.ctx, Date.now() + 60000);
      throw failed.reason;
    }
  }

  // RPC is available only through the namespace binding, never through the public HTTP API.
  async firePushTimers() {
    await this.push.alarm();
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const mcp = url.pathname === '/mcp' || url.pathname.startsWith('/mcp/');
    if (!url.pathname.startsWith('/api/') && !mcp && !url.pathname.startsWith('/.well-known/')) return env.ASSETS.fetch(request);
    const origin = request.headers.get('origin');
    const allowed = new Set([env.ORIGIN, 'capacitor://localhost', 'https://localhost', 'http://localhost']);
    const allowedOrigin = !!origin && allowed.has(origin);
    if (origin && !allowedOrigin) return json({ error: 'origin refused' }, 403);
    if (request.method === 'OPTIONS') {
      if (!allowedOrigin) return json({ error: 'origin required' }, 403);
      return new Response(null, { status: 204, headers: {
        'access-control-allow-origin': origin, 'access-control-allow-credentials': 'true',
        'access-control-allow-methods': 'GET, HEAD, POST, PUT, DELETE, OPTIONS',
        'access-control-allow-headers': 'content-type, authorization, x-device-id, x-opengym-account, cf-access-client-id, cf-access-client-secret, mcp-protocol-version, mcp-session-id', 'vary': 'Origin'
      } });
    }
    const nativePairing = request.method === 'POST' && ['/api/pair/redeem', '/api/watch/redeem'].includes(url.pathname);
    if (!mcp && !['GET', 'HEAD'].includes(request.method) && !allowedOrigin && !nativePairing && !request.headers.get('authorization')?.startsWith('Bearer ')) return json({ error: 'origin required' }, 403);
    // Reject floods before they reach the single database object or password verification.
    const key = 'opengym-personal:' + (request.headers.get('cf-connecting-ip') || 'unknown');
    let { success } = await env.API_RATE_LIMITER.limit({ key });
    if (success && request.method === 'POST' && (url.pathname.startsWith('/api/login/') ||
        url.pathname.startsWith('/api/register/') || url.pathname.startsWith('/api/device-link/') || nativePairing)) {
      ({ success } = await env.AUTH_RATE_LIMITER.limit({ key }));
    }
    const response = success ? await (mcp ? mcpRequest(request, env) : env.GYM.get(env.GYM.idFromName('personal')).fetch(request))
      : json({ error: 'Too many requests. Try again shortly.', code: 'rate-limited', retryAfter: 60 }, 429, { 'Retry-After': '60' });
    const out = new Response(response.body, response);
    out.headers.set('x-content-type-options', 'nosniff');
    out.headers.set('referrer-policy', 'same-origin');
    out.headers.set('cache-control', 'no-store');
    if (allowedOrigin) {
      out.headers.set('access-control-allow-origin', origin);
      out.headers.set('access-control-allow-credentials', 'true');
      out.headers.set('vary', 'Origin');
    }
    return out;
  }
};

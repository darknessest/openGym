import { json, readJson, HttpError } from './http.js';
import { createHash } from 'node:crypto';
import { scheduleAlarm } from './alarms.js';
import { commitState } from './state.js';
import { isDue, reviewedAtOf, retryWaiting } from '../api/coach/core/due.js';
import { HTTP_PROVIDERS, baseUrlFor, validateBaseUrl, validateHeaders } from '../api/coach/core/providers.js';
import anthropic from '../api/coach/core/adapters/anthropic.js';
import openai from '../api/coach/core/adapters/openai.js';
import gemini from '../api/coach/core/adapters/gemini.js';
import minimax from '../api/coach/core/adapters/minimax.js';
import openrouter from '../api/coach/core/adapters/openrouter.js';
import compatible from '../api/coach/core/adapters/compatible.js';
import { sseEvents } from '../api/coach/core/adapters/http.js';
import { runPipeline } from '../api/coach/core/pipeline.js';
import * as payloadLib from '../api/coach/core/payload.js';
import { hashPlan } from '../api/coach/core/plan-hash.js';
import { waitingProposal } from '../api/coach/core/pending.js';
import { extractJSON } from '../api/coach/core/parse.js';
import { classifyFailure, userMessageFor } from '../api/coach/core/failure.js';
import { SYSTEM_PROMPT } from '../api/coach/core/system-prompt.js';
import * as plan from '../api/coach/chatgpt-plan.js';

const ADAPTERS = { anthropic, openai, gemini, minimax, openrouter, compatible };
const CONFIG = 'coach:config';
const JOBS = 'coach:job:';
const PENDING = 'coach:chatgpt:pending';
const JOB_TIMEOUT = 5 * 60000;
const SHARED = 'This ChatGPT plan belongs to the instance owner. Use that profile or ask the admin to configure an API key.';
const encoder = new TextEncoder();

// Account mutations use this synchronously, in the same transaction as revocation.
export function cleanupCoachUser(store, uid, { sessionKey, remove = false, owner = false } = {}) {
  const cancelled = new Set();
  for (const { key, value } of store.list(JOBS)) {
    if (value.uid === uid && (!sessionKey || value.sessionKey === sessionKey)) {
      cancelled.add(value.id);
      store.delete(key);
    }
  }
  const rec = store.get('coach:user:' + uid);
  if (remove) store.delete('coach:user:' + uid);
  else if (rec && (!sessionKey || cancelled.has(rec.current?.id))) {
    store.put('coach:user:' + uid, { ...rec, current: null, pending: sessionKey ? rec.pending : null });
  }
  if (!sessionKey || cancelled.has(store.get('coach:test:' + uid)?.id)) store.delete('coach:test:' + uid);
  const pending = store.get(PENDING);
  if (pending?.uid === uid && (!sessionKey || pending.sessionKey === sessionKey)) store.delete(PENDING);
  const cfg = store.get(CONFIG);
  if (owner && cfg?.auth?.chatgpt?.ownerUid === uid) {
    const auth = { ...cfg.auth };
    delete auth.chatgpt;
    const { chatgptClient, ...rest } = cfg;
    store.put(CONFIG, { ...rest, auth, revision: (cfg.revision || 0) + 1 });
  }
}

// No remote error text is persisted or returned: a provider can echo an arbitrary API key,
// refresh token, or even the submitted training data in its error body.
const FAILURES = {
  off: 'The Coach configuration changed. Try again.',
  consent: 'The Coach needs your go-ahead first.',
  auth: 'The provider rejected the credential. Connect it again.',
  quota: 'The provider is out of quota or is rate limiting this instance.',
  schema: 'The provider rejected the request format. Try another model.',
  outage: 'The provider is having an outage. Try again later.',
  unreachable: 'The provider could not be reached.',
  timeout: 'The provider did not answer within the job budget.',
  unusable: 'The provider answered, but the answer failed Coach validation.',
  restart: 'The Worker restarted while this job was running. Try again.',
  toolarge: 'The training payload is too large.',
  noworkout: 'That workout could not be found.',
  internal: 'The Coach could not complete this job.'
};

export class Coach {
  constructor(store, env, ctx, push) {
    this.store = store;
    this.env = env;
    this.ctx = ctx;
    this.push = push;
    this.keyId = createHash('sha256').update('opengym-coach-key-id:' + (env.SESSION_SECRET || '')).digest('hex');
    this.renewing = null;
    this.alarming = null;
    this.aborts = new Map();
  }

  config() {
    return this.store.get(CONFIG, {
      enabled: false, provider: plan.on(this.env) ? 'chatgpt' : 'anthropic',
      revision: 0, auth: {}, models: {}, providerOptions: {},
      caps: { perProfileDaily: 10, instanceDaily: 50 }, maxMessageLen: 1000,
      maxOutputTokens: 16000, web: false, routinesUrl: null, log: []
    });
  }

  providers() {
    return Object.assign(Object.create(null), HTTP_PROVIDERS,
      plan.on(this.env) ? { chatgpt: { label: 'ChatGPT plan (preview)', runtime: 'HTTPS', signIn: 'chatgpt' } } : {});
  }

  assertUser(user, admin = false, owner = false) {
    const current = user && this.store.get('users', []).find(u => u.id === user.id);
    if (!current || current.disabled || (user.sv !== undefined && user.sv !== current.sv)) {
      throw new HttpError(401, 'not signed in');
    }
    if (user._sessionKey) {
      const session = this.store.get(user._sessionKey);
      if (!session || session.uid !== current.id || session.exp <= Date.now() || session.sv !== current.sv) {
        throw new HttpError(401, 'not signed in');
      }
    }
    if (admin && !current.admin && !current.owner) throw new HttpError(403, 'admin required');
    if (owner && !current.owner) throw new HttpError(403, 'Sign in with the instance owner profile to connect its ChatGPT plan.');
    return current;
  }

  enabled(cfg = this.config()) {
    return !/^(1|true|yes|on)$/i.test(this.env.COACH_DISABLED || '') && !!cfg.enabled && !!this.providers()[cfg.provider];
  }

  connected(uid, cfg = this.config()) {
    const meta = this.providers()[cfg.provider];
    if (!meta || !this.env.SESSION_SECRET) return false;
    const rec = cfg.auth[cfg.provider];
    if (cfg.provider === 'chatgpt') {
      const owner = this.store.get('users', []).find(u => u.id === rec?.ownerUid && u.owner && !u.disabled);
      return rec?.data?.keyId === this.keyId && !!owner && owner.sv === rec.ownerSv && (!uid || uid === rec.ownerUid);
    }
    return !!baseUrlFor(cfg.provider, cfg) && (rec ? rec.data?.keyId === this.keyId : !!meta.keyOptional);
  }

  publicConfig(user) {
    const cfg = this.config();
    if (!user || !this.enabled(cfg) || !this.connected(user.id, cfg)) return null;
    const meta = this.providers()[cfg.provider];
    return {
      enabled: true, provider: cfg.provider, providerLabel: meta.label, authMode: 'instance',
      community: false, web: !!cfg.web && !!meta.web,
      ...(cfg.routinesUrl ? { routinesUrl: cfg.routinesUrl } : {})
    };
  }

  guard(user) {
    this.assertUser(user);
    const cfg = this.config();
    if (!this.enabled(cfg) || !this.connected(null, cfg)) throw new HttpError(503, 'the Coach is not set up on this instance', 'off');
    if (!this.connected(user.id, cfg)) throw new HttpError(409, SHARED, 'shared');
    return cfg;
  }

  async key() {
    if (!this.env.SESSION_SECRET) throw new HttpError(503, 'server secrets are not configured');
    const digest = await crypto.subtle.digest('SHA-256', encoder.encode('opengym-coach:' + this.env.SESSION_SECRET));
    return crypto.subtle.importKey('raw', digest, 'AES-GCM', false, ['encrypt', 'decrypt']);
  }

  async encrypt(value, provider, ownerUid = '') {
    const key = await this.key();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(provider + ':' + ownerUid) }, key, encoder.encode(JSON.stringify(value)));
    return { keyId: this.keyId, iv: Array.from(iv), ciphertext: Array.from(new Uint8Array(data)) };
  }

  async decrypt(rec, provider) {
    if (!rec?.data || rec.data.keyId !== this.keyId) return null;
    try {
      const key = await this.key();
      const bytes = await crypto.subtle.decrypt({
        name: 'AES-GCM', iv: new Uint8Array(rec.data.iv),
        additionalData: encoder.encode(provider + ':' + (rec.ownerUid || ''))
      }, key, new Uint8Array(rec.data.ciphertext));
      return JSON.parse(new TextDecoder().decode(bytes));
    } catch { return null; }
  }

  // A rotating refresh token must have exactly one user, including model-list requests
  // that can interleave with an alarm while it awaits a provider response.
  async credential(cfg, uid) {
    const provider = cfg.provider;
    const rec = cfg.auth[provider];
    if (provider !== 'chatgpt') {
      const cred = await this.decrypt(rec, provider);
      if (!cred?.token && (rec || !this.providers()[provider]?.keyOptional)) throw new HttpError(503, 'No readable API key is configured.', 'off');
      if ((this.config().revision || 0) !== (cfg.revision || 0) || this.config().auth[provider]?.id !== rec?.id) throw new HttpError(409, FAILURES.off, 'off');
      return cred;
    }
    if (!this.connected(uid, cfg)) throw new HttpError(409, SHARED, 'shared');
    if (this.renewing) {
      await this.renewing;
      const fresh = this.config();
      if ((fresh.revision || 0) !== (cfg.revision || 0) || fresh.auth.chatgpt?.id !== rec?.id) throw new HttpError(409, FAILURES.off, 'off');
      return this.credential(fresh, uid);
    }
    const renew = (async () => {
      const cred = await this.decrypt(rec, provider);
      if (!cred?.token) throw new HttpError(503, 'Sign in with ChatGPT again.', 'auth');
      if (this.config().auth.chatgpt?.id !== rec.id || !this.connected(uid, this.config())) throw new HttpError(409, FAILURES.off, 'off');
      let next = cred;
      if (plan.needsRefresh(cred)) {
        const result = await plan.refreshCredential(this.fetchAuth.bind(this), cred);
        if (!result.ok) throw new HttpError(502, 'ChatGPT could not renew the sign-in. Sign in again.', 'auth');
        if (!plan.planGranted(result.cred.scope)) throw new HttpError(403, 'ChatGPT plan use is no longer allowed.', 'auth');
        next = result.cred;
        const data = await this.encrypt(next, provider, rec.ownerUid);
        const current = this.config();
        // Persist rotated refresh credentials even when only model/config changed. The
        // caller's revision fence below still rejects inference using that stale config.
        if (current.auth.chatgpt?.id !== rec.id || current.auth.chatgpt?.ownerUid !== rec.ownerUid ||
            current.auth.chatgpt?.ownerSv !== rec.ownerSv || !this.store.get('users', []).some(u =>
              u.id === rec.ownerUid && u.owner && !u.disabled && u.sv === rec.ownerSv)) {
          throw new HttpError(409, FAILURES.off, 'off');
        }
        this.store.put(CONFIG, { ...current, auth: { ...current.auth, chatgpt: { ...current.auth.chatgpt, data } } });
      }
      const current = this.config();
      if ((current.revision || 0) !== (cfg.revision || 0) || current.auth.chatgpt?.id !== rec.id || !this.connected(uid, current)) {
        throw new HttpError(409, FAILURES.off, 'off');
      }
      return next;
    })();
    this.renewing = renew;
    try { return await renew; }
    finally { if (this.renewing === renew) this.renewing = null; }
  }

  async fetchAuth(url, init = {}) {
    const response = await fetch(url, { ...init, redirect: 'manual', signal: AbortSignal.timeout(20000) });
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel();
      throw new HttpError(502, 'Provider redirects are refused.', 'provider');
    }
    return response;
  }

  async schedule(at = Date.now() + 1000) {
    return scheduleAlarm(this.ctx, at);
  }

  // Every actual provider fetch is gated again after token decryption/refresh and after
  // adapter retries/model discovery. A job never sends a repair after its consent changed.
  transport(check, signal) {
    return async (url, init = {}) => {
      check();
      const target = new URL(url);
      if (target.protocol !== 'https:' || target.username || target.password) throw new HttpError(400, 'HTTPS provider endpoint required.', 'provider');
      const response = await fetch(url, {
        ...init, redirect: 'manual',
        signal: AbortSignal.any([signal, ...(init.signal ? [init.signal] : [])])
      });
      check();
      if (response.status >= 300 && response.status < 400) {
        await response.body?.cancel();
        throw new HttpError(502, 'Provider redirects are refused.', 'provider');
      }
      return response;
    };
  }

  chatgptAdapter(cfg, uid, check) {
    const coach = this;
    return {
      spawns: false,
      async models(_cfg, _env, opts = {}) {
        try {
          const cred = await coach.credential(cfg, uid);
          check();
          const signal = opts.signal || AbortSignal.timeout(20000);
          const response = await coach.transport(check, signal)(plan.RESOURCE + '/models', { headers: { authorization: 'Bearer ' + cred.token } });
          const data = await response.json();
          check();
          if (!response.ok) return { ok: false, error: response.status + ' model list refused', models: [] };
          const list = Array.isArray(data.models)
            ? data.models.filter(m => m?.visibility === 'list').map(m => m.slug)
            : (data.data || []).map(m => m.id);
          return { ok: true, models: list.filter(m => typeof m === 'string' && m) };
        } catch (error) {
          if (error instanceof HttpError) throw error;
          return { ok: false, error: 'could not reach api.openai.com', models: [] };
        }
      },
      async invoke({ prompt, system, schema, model, signal, timeoutMs = JOB_TIMEOUT }) {
        try {
          let chosen = model;
          if (!chosen) {
            const listed = await this.models(null, null, { signal });
            chosen = listed.ok ? listed.models[0] : null;
            if (!chosen) return { code: 1, text: '', stderr: listed.error || 'no model available' };
          }
          const cred = await coach.credential(cfg, uid);
          check();
          const response = await coach.transport(check, signal || AbortSignal.timeout(timeoutMs))(plan.RESOURCE + '/responses', {
            method: 'POST', headers: { authorization: 'Bearer ' + cred.token, 'content-type': 'application/json', accept: 'text/event-stream' },
            body: JSON.stringify(plan.responsesBody({ model: chosen, prompt, instructions: SYSTEM_PROMPT + (system ? '\n\n' + system : ''), schema }))
          });
          const raw = await response.text();
          check();
          if (!response.ok) return { code: 1, text: '', stderr: response.status + ' ChatGPT request refused' };
          const out = plan.foldResponses(sseEvents(raw));
          return out.ok ? { code: 0, text: out.text, stderr: '' } : { code: 1, text: '', stderr: out.error };
        } catch (error) {
          if (error instanceof HttpError) throw error;
          return { code: 1, text: '', timedOut: signal?.aborted || error.name === 'AbortError' || error.name === 'TimeoutError', stderr: 'could not reach api.openai.com' };
        }
      }
    };
  }

  async provider(cfg, uid, check) {
    if (cfg.provider === 'chatgpt') return { adapter: this.chatgptAdapter(cfg, uid, check), env: {} };
    const cred = await this.credential(cfg, uid);
    check();
    return { adapter: ADAPTERS[cfg.provider], env: { [HTTP_PROVIDERS[cfg.provider].apiKeyEnv]: cred?.token || '' } };
  }

  record(uid) {
    return this.store.get('coach:user:' + uid, { daily: null, current: null, pending: null, history: [] });
  }

  status(uid, cfg) {
    const rec = this.record(uid);
    if (rec.pending?.expiresAt < Date.now()) {
      rec.history = [...rec.history, { id: rec.pending.id, kind: rec.pending.kind, outcome: 'expired', at: Date.now() }].slice(-40);
      rec.pending = null;
      this.store.put('coach:user:' + uid, rec);
    }
    return {
      job: rec.current, pending: rec.pending,
      cap: { used: rec.daily?.date === new Date().toISOString().slice(0, 10) ? rec.daily.count : 0, limit: cfg.caps.perProfileDaily },
      last: rec.history.at(-1) || null, maxMessageLen: cfg.maxMessageLen
    };
  }

  checkJob(job) {
    const cfg = this.config();
    const user = this.store.get('users', []).find(u => u.id === job.uid);
    if (!user || user.disabled || user.sv !== job.sv) throw new HttpError(401, 'account changed', 'consent');
    if (job.sessionKey) {
      const session = this.store.get(job.sessionKey);
      if (!session || session.uid !== job.uid || session.sv !== user.sv || session.exp <= Date.now()) throw new HttpError(401, 'session ended', 'consent');
    }
    if ((cfg.revision || 0) !== job.revision || !this.enabled(cfg) || !this.connected(job.uid, cfg)) throw new HttpError(409, FAILURES.off, 'off');
    if (job.kind === 'test') {
      if ((!user.admin && !user.owner) || this.store.get('coach:test:' + job.uid)?.id !== job.id) throw new HttpError(403, 'test cancelled', 'off');
      return;
    }
    const state = this.store.get('state:' + job.uid);
    const privacy = JSON.stringify({ consent: state?.coach?.consent, share: state?.coach?.share, web: state?.coach?.web });
    if (!state?.coach?.consent?.agreedAt || state.modules?.coach === false || privacy !== job.privacy || this.record(job.uid).current?.id !== job.id) {
      throw new HttpError(403, FAILURES.consent, 'consent');
    }
  }

  async enqueue(user, body, kind, scheduled = false) {
    await this.schedule();
    const cfg = this.guard(user);
    const current = this.assertUser(user);
    const rec = this.record(user.id);
    if (rec.current || this.store.list(JOBS).some(row => row.value.uid === user.id)) throw new HttpError(409, 'the Coach is already thinking about your training', 'busy');
    const state = this.store.get('state:' + user.id);
    if (!state?.coach?.consent?.agreedAt || state.modules?.coach === false) throw new HttpError(403, 'the Coach needs your go-ahead first', 'consent');
    const date = new Date().toISOString().slice(0, 10);
    const used = rec.daily?.date === date ? rec.daily.count : 0;
    const instanceUsed = cfg.daily?.date === date ? cfg.daily.count : 0;
    if ((cfg.caps.perProfileDaily && used >= cfg.caps.perProfileDaily) || (cfg.caps.instanceDaily && instanceUsed >= cfg.caps.instanceDaily)) {
      throw new HttpError(429, 'the Coach is taking a rest day, try again tomorrow', 'cap');
    }
    const today = body.today && typeof body.today === 'object' && !Array.isArray(body.today) ? body.today : null;
    if (kind === 'ask' && (typeof body.text !== 'string' || !body.text.trim())) throw new HttpError(400, 'a question is required', 'invalid');
    if (kind === 'adapt' && (!Array.isArray(today?.entries) || !Number.isInteger(body.entry) || body.entry < 0 || body.entry >= today.entries.length)) {
      throw new HttpError(400, 'a running workout and one of its exercises are required', 'invalid');
    }
    const job = {
      id: crypto.randomUUID(), uid: user.id, sv: current.sv, kind, state: 'queued', startedAt: Date.now(), revision: cfg.revision || 0,
      sessionKey: user._sessionKey || null, trigger: scheduled ? 'scheduled' : 'manual',
      privacy: JSON.stringify({ consent: state.coach.consent, share: state.coach.share, web: state.coach.web }),
      intake: kind === 'create' && body.intake && typeof body.intake === 'object' && !Array.isArray(body.intake) ? body.intake : null,
      refine: kind === 'create' && typeof body.refine === 'string' ? body.refine.slice(0, cfg.maxMessageLen) : null,
      note: typeof (body.text ?? body.note) === 'string' ? (body.text ?? body.note).trim().slice(0, cfg.maxMessageLen) : null,
      lang: payloadLib.langTag(body.lang),
      workoutId: typeof body.workoutId === 'string' ? body.workoutId.slice(0, 40) : null,
      today: kind === 'ask' || kind === 'adapt' ? today : null,
      focus: kind === 'adapt' ? { entry: body.entry, reason: typeof body.reason === 'string' ? body.reason.slice(0, 16) : 'other' } : null,
      activeId: kind === 'adapt' && typeof body.activeId === 'string' ? body.activeId.slice(0, 64) : null,
      vitals: body.vitals && typeof body.vitals === 'object' && !Array.isArray(body.vitals) ? body.vitals : null,
      routines: kind === 'ask' && Array.isArray(body.routines) ? body.routines.slice(0, 8) : null
    };
    this.store.transaction(() => {
      this.store.put(JOBS + job.id, job);
      this.store.put('coach:user:' + user.id, {
        ...rec, privacy: job.privacy, daily: { date, count: used + 1 }, current: { id: job.id, kind, state: 'queued', startedAt: job.startedAt }
      });
      this.store.put(CONFIG, { ...cfg, daily: { date, count: instanceUsed + 1 } });
    });
    return json({ job: { id: job.id } }, 202);
  }

  async execute(job) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), JOB_TIMEOUT);
    this.aborts.set(job.uid, ctl);
    try {
      this.checkJob(job);
      const cfg = this.config();
      job.state = 'running';
      this.store.transaction(() => {
        this.store.put(JOBS + job.id, job);
        if (job.kind !== 'test') {
          const rec = this.record(job.uid);
          this.store.put('coach:user:' + job.uid, { ...rec, current: { ...rec.current, state: 'running' } });
        }
      });
      const check = () => {
        this.checkJob(job);
        if (ctl.signal.aborted) throw new HttpError(408, FAILURES.timeout, 'timeout');
      };
      const { adapter, env } = await this.provider(cfg, job.uid, check);
      check();
      const fetchImpl = this.transport(check, ctl.signal);
      const model = cfg.models[cfg.provider] || this.providers()[cfg.provider].defaultModel || null;
      if (job.kind === 'test') {
        const result = await adapter.invoke({ cfg, env, model, fetch: fetchImpl, signal: ctl.signal, timeoutMs: JOB_TIMEOUT, maxTokens: cfg.maxOutputTokens,
          prompt: 'Reply with exactly this JSON object and nothing else: {"coach_contract":1,"ok":true}' });
        check();
        const parsed = result.code === 0 ? extractJSON(result.text) : null;
        if (result.code !== 0 || parsed?.error || parsed?.value?.ok !== true) {
          return this.finish(job, { outcome: 'failed', errorClass: result.timedOut ? 'timeout' : result.code !== 0 ? classifyFailure({ text: result.stderr }) : 'unusable' });
        }
        return this.finish(job, { outcome: 'ready', version: 'HTTPS · ' + this.providers()[cfg.provider].label });
      }
      const state = this.store.get('state:' + job.uid);
      if (job.kind === 'debrief' && !payloadLib.findWorkout(state, job.workoutId)) return this.finish(job, { outcome: 'failed', errorClass: 'noworkout' });
      const pendingCreate = job.refine ? this.record(job.uid).pending : null;
      const useWeb = job.kind === 'ask' && !!cfg.web && !!this.providers()[cfg.provider].web && state.coach.web === true;
      const hmac = await crypto.subtle.importKey('raw', encoder.encode(this.env.SESSION_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      const signature = await crypto.subtle.sign('HMAC', hmac, encoder.encode('coach-handle:' + job.uid));
      check();
      const handle = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '').slice(0, 16);
      const payload = payloadLib.build(state, { ...job, handle, previous: pendingCreate?.bundle || null, web: useWeb });
      if (JSON.stringify(payload).length > payloadLib.MAX_PAYLOAD_CHARS) return this.finish(job, { outcome: 'failed', errorClass: 'toolarge' });
      const attempt = await runPipeline({
        adapter, cfg, kind: job.kind, payload, model, timeoutMs: JOB_TIMEOUT,
        invokeOpts: { env, fetch: fetchImpl, signal: ctl.signal, maxTokens: cfg.maxOutputTokens, web: useWeb }
      });
      check();
      if (!attempt.ok) return this.finish(job, { outcome: 'failed', errorClass: attempt.errorClass });
      if (attempt.nochange) return this.finish(job, { outcome: 'nochange', pending: null, reading: attempt.reading });
      const kind = attempt.kind || job.kind;
      const pending = {
        ...attempt.result, id: job.id, kind, trigger: job.trigger, createdAt: Date.now(), expiresAt: Date.now() + 14 * 86400000,
        planHash: hashPlan(payloadLib.canonicalPlan(state)), iteration: job.refine ? (pendingCreate?.iteration || 1) + 1 : 1,
        ...(job.kind === 'debrief' ? { workout: payloadLib.workoutMeta(state, job.workoutId) } : {}),
        ...(kind === 'ask' || kind === 'adapt' ? { prev: waitingProposal(this.record(job.uid).pending) } : {}),
        ...(kind !== job.kind ? { from: job.kind } : {}),
        ...(job.kind === 'adapt' ? { activeId: job.activeId, focus: payload.focus } : {})
      };
      return this.finish(job, { outcome: 'ready', pending });
    } catch (error) {
      return this.finish(job, { outcome: 'failed', errorClass: ctl.signal.aborted ? 'timeout' : error instanceof HttpError ? error.code || 'off' : 'internal' });
    } finally {
      clearTimeout(timer);
      if (this.aborts.get(job.uid) === ctl) this.aborts.delete(job.uid);
    }
  }

  finish(job, result) {
    let notification = null;
    this.store.transaction(() => {
      this.store.delete(JOBS + job.id);
      const cfg = this.config();
      const at = Date.now();
      const entry = { at, kind: job.kind, trigger: job.trigger || 'manual', outcome: result.outcome, errorClass: result.errorClass || null, ms: at - job.startedAt };
      this.store.put(CONFIG, { ...cfg, log: [...cfg.log, entry].slice(-100) });
      // Forget/account deletion/consent withdrawal must never recreate personal results.
      try { this.checkJob(job); } catch {
        if (job.kind === 'test') {
          if (this.store.get('coach:test:' + job.uid)?.id === job.id) this.store.delete('coach:test:' + job.uid);
        } else {
          const rec = this.record(job.uid);
          if (rec.current?.id === job.id) {
            const user = this.store.get('users', []).find(u => u.id === job.uid && !u.disabled && u.sv === job.sv);
            const state = this.store.get('state:' + job.uid);
            const privacy = JSON.stringify({ consent: state?.coach?.consent, share: state?.coach?.share, web: state?.coach?.web });
            const history = user && state?.coach?.consent?.agreedAt && privacy === job.privacy
              ? [...rec.history, { id: job.id, ...entry, outcome: 'failed', errorClass: 'off', message: FAILURES.off }].slice(-40) : [];
            this.store.put('coach:user:' + job.uid, { ...rec, current: null, pending: history.length ? rec.pending : null, history });
          }
        }
        return;
      }
      if (job.kind === 'test') {
        this.store.put('coach:test:' + job.uid, { id: job.id, pending: false, ok: result.outcome === 'ready',
          ...(result.version ? { version: result.version } : {}),
          ...(result.errorClass ? { error: FAILURES[result.errorClass] || FAILURES.internal } : {}) });
        return;
      }
      const rec = this.record(job.uid);
      const last = { id: job.id, ...entry,
        ...(result.errorClass ? { message: userMessageFor(result.errorClass) || FAILURES[result.errorClass] || FAILURES.internal } : {}),
        ...(result.reading ? { reading: String(result.reading).slice(0, 4000) } : {}) };
      this.store.put('coach:user:' + job.uid, {
        ...rec, current: null, pending: result.pending !== undefined ? result.pending : rec.pending,
        history: [...rec.history, last].slice(-40)
      });
      if (result.pending?.changes?.length) notification = result.pending;
    });
    if (notification && this.push) this.ctx.waitUntil(this.notify(job, notification));
  }

  async notify(job, pending) {
    // Only generic copy leaves the app, never the proposal or training data.
    const valid = () => {
      const cfg = this.config();
      const user = this.store.get('users', []).find(u => u.id === job.uid);
      const state = this.store.get('state:' + job.uid);
      const session = job.sessionKey && this.store.get(job.sessionKey);
      return user && !user.disabled && user.sv === job.sv && this.enabled(cfg) && this.connected(job.uid, cfg) &&
        (cfg.revision || 0) === job.revision && (!job.sessionKey || (session?.uid === job.uid && session.sv === user.sv && session.exp > Date.now())) &&
        state?.coach?.consent?.agreedAt && state.modules?.coach !== false &&
        JSON.stringify({ consent: state.coach.consent, share: state.coach.share, web: state.coach.web }) === job.privacy &&
        this.record(job.uid).pending?.id === pending.id && pending.expiresAt > Date.now();
    };
    try {
      const count = pending.changes.length;
      if (valid()) await this.push.send(job.uid, { title: 'Your Coach has been reading',
        body: count === 1 ? '1 suggestion after this week' : `${count} suggestions after this week`,
        tag: 'coach-proposal', url: '#/coach' }, undefined, valid);
    } catch (error) { console.error('Coach notification failed', error.name); }
  }

  async wake() {
    for (const { key, value: rec } of this.store.list('coach:user:')) {
      const uid = key.slice('coach:user:'.length), state = this.store.get('state:' + uid);
      const privacy = JSON.stringify({ consent: state?.coach?.consent, share: state?.coach?.share, web: state?.coach?.web });
      if (!state?.coach?.consent?.agreedAt || (rec.privacy && rec.privacy !== privacy)) {
        this.aborts.get(uid)?.abort();
        for (const { key: jobKey, value: job } of this.store.list(JOBS)) if (job.uid === uid && job.kind !== 'test') this.store.delete(jobKey);
        this.store.put(key, { daily: rec.daily, privacy, current: null, pending: null, history: [] });
      }
    }
    for (const { value: job } of this.store.list(JOBS)) {
      try { this.checkJob(job); }
      catch {
        this.aborts.get(job.uid)?.abort();
        this.finish(job, { outcome: 'failed', errorClass: 'off' });
      }
    }
    const cfg = this.config();
    const cadence = this.enabled(cfg) && this.connected(null, cfg) && this.store.get('users', []).some(user => {
      const state = this.store.get('state:' + user.id);
      return !user.disabled && this.connected(user.id, cfg) && state?.coach?.consent?.agreedAt &&
        state.modules?.coach !== false && state.coach.cadence && state.coach.cadence !== 'off';
    });
    if (this.store.list(JOBS).length || cadence) await this.schedule();
    else if (this.store.get(PENDING)) await this.schedule(this.store.get(PENDING).expiresAt);
  }

  async cadence() {
    const cfg = this.config();
    if (!this.enabled(cfg) || !this.connected(null, cfg)) return;
    for (const user of this.store.get('users', [])) {
      const state = this.store.get('state:' + user.id);
      if (user.disabled || !this.connected(user.id, cfg) || !state?.coach?.consent?.agreedAt || state.modules?.coach === false) continue;
      const status = this.status(user.id, cfg), rec = this.record(user.id);
      if (status.job || status.pending || retryWaiting(rec.history)) continue;
      const tz = state.reminder?.tz || 'UTC';
      let parts;
      try { parts = new Intl.DateTimeFormat('en-US', { timeZone: tz, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', weekday: 'short' }).formatToParts(new Date()); }
      catch { continue; }
      const p = Object.fromEntries(parts.map(part => [part.type, part.value]));
      const now = { date: `${p.year}-${p.month}-${p.day}`, hhmm: `${p.hour}:${p.minute}`, weekday: ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].indexOf(p.weekday) };
      if (!isDue(state.coach, state, now, reviewedAtOf(rec.history), tz)) continue;
      try { await this.enqueue(user, { lang: state.lang }, 'review', true); }
      catch (error) { if (!(error instanceof HttpError)) throw error; }
    }
  }

  async alarm() {
    if (this.alarming) return this.alarming;
    const running = (async () => {
      const pending = this.store.get(PENDING);
      if (pending && pending.expiresAt <= Date.now()) this.store.delete(PENDING);
      await this.cadence();
      // A persisted 'running' job was interrupted; do not silently spend again.
      const jobs = this.store.list(JOBS).map(row => row.value).sort((a, b) => a.startedAt - b.startedAt);
      for (const job of jobs) {
        if (job.state === 'running') this.finish(job, { outcome: 'failed', errorClass: 'restart' });
      }
      const next = jobs.find(job => job.state === 'queued' && this.store.get(JOBS + job.id));
      if (next) {
        // A retry wakeup survives unexpected termination before bookkeeping completes.
        await this.schedule(Date.now() + JOB_TIMEOUT + 10000);
        if (this.store.get(JOBS + next.id)) await this.execute(next);
      }
    })();
    this.alarming = running;
    try { await running; }
    finally {
      this.alarming = null;
      const pending = this.store.get(PENDING);
      if (this.store.list(JOBS).length) await this.schedule();
      else {
        if (pending) await this.schedule(pending.expiresAt);
        const cfg = this.config();
        if (this.enabled(cfg) && this.connected(null, cfg)) await this.schedule(Date.now() + 60000);
      }
    }
  }

  async adminStatus(user) {
    const cfg = this.config();
    const meta = this.providers()[cfg.provider];
    const rec = cfg.auth[cfg.provider];
    const cred = await this.decrypt(rec, cfg.provider);
    this.assertUser(user, true);
    if ((this.config().revision || 0) !== (cfg.revision || 0)) return this.adminStatus(user);
    const auth = rec?.data ? { state: cred?.token ? 'connected' : 'unreadable', type: rec.type, account: rec.account || null, connectedAt: rec.connectedAt }
      : { state: meta?.keyOptional ? 'optional' : 'none' };
    const log = cfg.log;
    return json({
      disabledByEnv: /^(1|true|yes|on)$/i.test(this.env.COACH_DISABLED || ''), enabled: cfg.enabled,
      provider: cfg.provider, providerLabel: meta?.label,
      providers: Object.entries(this.providers()).map(([id, provider]) => ({
        id, label: provider.label, runtime: 'HTTPS', http: !!provider.http, apiKey: !!provider.apiKeyEnv,
        baseUrl: !!provider.baseUrl, keyOptional: !!provider.keyOptional, keyPlaceholder: provider.keyPlaceholder || null,
        defaultModel: provider.defaultModel || null, keyUrl: provider.keyUrl || null, signIn: id === 'chatgpt' ? 'chatgpt' : null,
        web: !!provider.web, connected: !!cfg.auth[id]?.data, setupToken: false, deviceLogin: false, oauth: false
      })),
      models: cfg.models, model: cfg.models[cfg.provider] || meta?.defaultModel || null,
      baseUrl: cfg.provider === 'chatgpt' ? plan.RESOURCE : baseUrlFor(cfg.provider, cfg),
      headers: cfg.providerOptions[cfg.provider]?.headers || null, knownModels: null,
      caps: cfg.caps, maxMessageLen: cfg.maxMessageLen, maxOutputTokens: cfg.maxOutputTokens,
      community: false, web: cfg.web, routinesUrl: cfg.routinesUrl,
      runtime: { ok: !!meta && (cfg.provider === 'chatgpt' || !!baseUrlFor(cfg.provider, cfg)), version: 'Cloudflare Workers · HTTPS', error: null, worker: true },
      authMode: 'instance', boundUid: rec?.ownerUid || null, auth,
      unprivileged: { ok: true, dropped: false, why: 'this provider runs no child process' },
      jobsToday: cfg.daily?.date === new Date().toISOString().slice(0, 10) ? cfg.daily.count : 0,
      lastSuccess: [...log].reverse().find(e => e.outcome === 'ready' || e.outcome === 'nochange') || null,
      lastError: [...log].reverse().find(e => e.outcome === 'failed') || null, recent: log.slice(-20).reverse(),
      worker: true
    });
  }

  updateConfig(body) {
    const cfg = this.config();
    const provider = body.provider ?? cfg.provider;
    const meta = typeof provider === 'string' ? this.providers()[provider] : null;
    if (!meta) throw new HttpError(400, 'unknown provider');
    const next = { ...cfg, provider, revision: (cfg.revision || 0) + 1 };
    if (body.enabled !== undefined) next.enabled = !!body.enabled;
    if (body.model !== undefined) {
      if (typeof body.model !== 'string' || body.model.length > 160) throw new HttpError(400, 'invalid model');
      next.models = { ...cfg.models, [provider]: body.model.trim() || null };
    }
    if (body.baseUrl !== undefined || body.headers !== undefined) {
      if (!meta.baseUrl) throw new HttpError(400, 'this provider has a fixed endpoint');
      const options = { ...cfg.providerOptions[provider] };
      if (body.baseUrl !== undefined) {
        const valid = validateBaseUrl(body.baseUrl);
        if (!valid.ok) throw new HttpError(400, valid.error);
        if (!valid.value && !meta.defaultBase) throw new HttpError(400, 'enter an endpoint');
        if (valid.value && new URL(valid.value).protocol !== 'https:') throw new HttpError(400, 'Workers endpoints require https://');
        options.baseUrl = valid.value;
      }
      if (body.headers !== undefined) {
        const valid = validateHeaders(body.headers);
        if (!valid.ok) throw new HttpError(400, valid.error);
        options.headers = valid.value;
      }
      next.providerOptions = { ...cfg.providerOptions, [provider]: options };
      const before = baseUrlFor(provider, cfg), after = baseUrlFor(provider, next);
      if (before && after && new URL(before).host !== new URL(after).host) {
        next.auth = { ...cfg.auth };
        delete next.auth[provider];
      }
    }
    if (body.web !== undefined) next.web = !!body.web;
    if (body.community === true) throw new HttpError(400, 'Community comparisons are not enabled on this personal Worker.');
    if (body.routinesUrl !== undefined) {
      const value = String(body.routinesUrl || '').trim();
      if (value && value !== 'off') {
        let url;
        try { url = new URL(value); } catch { throw new HttpError(400, 'the routines index needs an https:// address, or off'); }
        if (url.protocol !== 'https:' || url.username || url.password || value.length > 300) throw new HttpError(400, 'invalid routines index');
      }
      next.routinesUrl = value || null;
    }
    if (body.caps !== undefined) {
      if (!body.caps || typeof body.caps !== 'object' || Array.isArray(body.caps)) throw new HttpError(400, 'invalid caps');
      next.caps = { ...cfg.caps };
      for (const [key, max] of [['perProfileDaily', 200], ['instanceDaily', 5000]]) {
        if (body.caps[key] !== undefined) {
          const value = body.caps[key];
          if (!Number.isInteger(value) || value < 0 || value > max) throw new HttpError(400, 'invalid daily limit');
          next.caps[key] = value;
        }
      }
    }
    for (const [key, min, max] of [['maxMessageLen', 200, 4000], ['maxOutputTokens', 1024, 65536]]) {
      if (body[key] !== undefined) {
        if (!Number.isInteger(body[key]) || body[key] < min || body[key] > max) throw new HttpError(400, 'invalid ' + key);
        next[key] = body[key];
      }
    }
    const before = baseUrlFor(cfg.provider, cfg), after = baseUrlFor(provider, next);
    const destinationChanged = provider !== cfg.provider ||
      (before ? new URL(before).host : null) !== (after ? new URL(after).host : null);
    this.store.transaction(() => {
      this.store.put(CONFIG, next);
      this.store.delete(PENDING);
      if (destinationChanged) {
        // A schedule approved for one provider cannot authorize sending data to another.
        // Use the normal sync commit so phones see the pause with a new revision/edit stamp.
        for (const { key, value: state } of this.store.list('state:')) {
          if (!state.coach?.cadence || state.coach.cadence === 'off') continue;
          commitState(this.store, key.slice('state:'.length), state, {
            baseRev: state._rev || 0,
            state: { ...state, coach: { ...state.coach, cadence: 'off' } }
          });
        }
      }
    });
    return json({ ok: true });
  }

  async startSignIn(user, body) {
    this.assertUser(user, true, true);
    if (!plan.on(this.env)) throw new HttpError(404, 'not found');
    let redirectUri;
    try { redirectUri = plan.loopbackRedirectUri(body.redirectUri); }
    catch { throw new HttpError(400, 'Start the local sign-in helper and supply its loopback callback address.'); }
    if (typeof body.relayNonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.relayNonce)) throw new HttpError(400, 'invalid sign-in helper nonce');
    let cfg = this.config();
    if (cfg.provider !== 'chatgpt') throw new HttpError(409, 'Choose ChatGPT as the provider first.');
    if (!cfg.chatgptHost) {
      cfg = { ...cfg, chatgptHost: plan.newHostId() };
      this.store.put(CONFIG, cfg);
    }
    const rec = cfg.auth.chatgpt;
    const previous = await this.decrypt(rec, 'chatgpt');
    await this.schedule(Date.now() + plan.PENDING_TTL_MS);
    this.assertUser(user, true, true);
    const current = this.config();
    if (current.revision !== cfg.revision || current.auth.chatgpt?.id !== rec?.id) throw new HttpError(409, FAILURES.off);
    const started = plan.startSignIn({ hostId: current.chatgptHost, clientId: current.chatgptClient || previous?.clientId || null,
      redirectUri, relayNonce: body.relayNonce });
    const data = await this.encrypt({ ...started.pending, accountSub: previous?.sub || null }, 'chatgpt-pending', user.id);
    this.assertUser(user, true, true);
    const fresh = this.config();
    if (fresh.revision !== current.revision || fresh.auth.chatgpt?.id !== rec?.id) throw new HttpError(409, FAILURES.off);
    this.store.put(PENDING, { uid: user.id, ownerUid: user.id, sv: user.sv, sessionKey: user._sessionKey,
      state: started.pending.state, redirectUri, data, revision: fresh.revision || 0, expiresAt: Date.now() + plan.PENDING_TTL_MS });
    return json({ url: started.url, redirect: redirectUri });
  }

  assertSignIn(user, pending) {
    this.assertUser(user, true, true);
    const active = this.store.get(PENDING), cfg = this.config();
    if (!pending || !active || pending.uid !== user.id || pending.sv !== user.sv || pending.sessionKey !== user._sessionKey ||
        active.state !== pending.state || active.expiresAt <= Date.now() || (cfg.revision || 0) !== pending.revision || cfg.provider !== 'chatgpt') {
      throw new HttpError(409, 'This sign-in expired or its owner session changed. Start again.');
    }
    return cfg;
  }

  async finishSignIn(user, body) {
    this.assertUser(user, true, true);
    if (!plan.on(this.env)) throw new HttpError(404, 'not found');
    const pending = this.store.get(PENDING);
    this.assertSignIn(user, pending);
    if (pending.exchanging) throw new HttpError(409, 'This sign-in is already being completed.');
    const secret = await this.decrypt(pending, 'chatgpt-pending');
    this.assertSignIn(user, pending);
    if (!secret || secret.redirectUri !== pending.redirectUri) throw new HttpError(400, 'This sign-in cannot be read. Start again.');
    const callback = plan.parseCallback(body.callback, secret);
    if (!callback.ok) throw new HttpError(400, callback.error);
    // Correlate first, then claim without an await: unrelated callbacks must leave the active
    // attempt intact, and concurrent valid callbacks must never exchange the same code twice.
    if (this.store.get(PENDING).exchanging) throw new HttpError(409, 'This sign-in is already being completed.');
    this.store.put(PENDING, { ...pending, exchanging: true });
    let exchanged = null;
    try {
      const result = await plan.exchangeCode(this.fetchAuth.bind(this), secret, callback.code, callback.clientId);
      if (!result.ok) throw new HttpError(502, 'ChatGPT could not complete the token exchange. Start again.');
      exchanged = plan.credentialOf(result.tokens, { clientId: callback.clientId, hostId: secret.hostId });
      this.assertSignIn(user, pending);
      const response = await this.fetchAuth(plan.JWKS_URL);
      this.assertSignIn(user, pending);
      if (!response.ok) throw new HttpError(502, 'Could not verify the ChatGPT sign-in.');
      const jwks = await response.json();
      this.assertSignIn(user, pending);
      const verified = plan.verifyIdToken(result.tokens.id_token, jwks, { audience: callback.clientId, nonce: secret.nonce });
      if (!verified.ok || typeof verified.claims?.sub !== 'string' || !verified.claims.sub) throw new HttpError(502, 'Could not verify the ChatGPT sign-in.');
      if (secret.accountSub && verified.claims.sub !== secret.accountSub) {
        throw new HttpError(400, 'Sign in with the connected ChatGPT account, or disconnect it before choosing another account.');
      }
      if (!plan.planGranted(result.tokens.scope)) throw new HttpError(400, 'Sign in again and allow ChatGPT plan use.');
      const cred = plan.credentialOf(result.tokens, { clientId: callback.clientId, hostId: secret.hostId, claims: verified.claims });
      const data = await this.encrypt(cred, 'chatgpt', user.id);
      const current = this.assertSignIn(user, pending);
      const account = typeof verified.claims.email === 'string' ? verified.claims.email.slice(0, 120) : null;
      this.store.transaction(() => {
        this.store.put(CONFIG, { ...current, revision: (current.revision || 0) + 1, chatgptClient: callback.clientId,
          auth: { ...current.auth, chatgpt: { id: crypto.randomUUID(), type: 'oauth', ownerUid: user.id, ownerSv: user.sv, account, data, connectedAt: new Date().toISOString() } } });
        this.store.delete(PENDING);
      });
      return json({ ok: true, account, usage: plan.USAGE_URL });
    } catch (error) {
      if (exchanged) await plan.revokeCredential(this.fetchAuth.bind(this), exchanged);
      if (this.store.get(PENDING)?.state === pending.state) this.store.delete(PENDING);
      if (error instanceof HttpError) throw error;
      throw new HttpError(502, 'Could not reach ChatGPT. Start sign-in again.');
    }
  }

  async handle(request, user) {
    const url = new URL(request.url);
    const path = url.pathname;
    const admin = path === '/api/admin/coach' || path.startsWith('/api/admin/coach/');
    if (!admin && !path.startsWith('/api/coach/')) return null;
    this.assertUser(user, admin);
    const account = request.headers.get('x-opengym-account');
    if (account && account !== String(user.id)) throw new HttpError(409, 'signed in as another account now', 'account-mismatch');
    const body = request.method === 'POST' ? await readJson(request) : {};
    this.assertUser(user, admin);
    if (admin) {
      if (request.method === 'GET' && path === '/api/admin/coach') return this.adminStatus(user);
      if (request.method === 'POST' && path === '/api/admin/coach/config') return this.updateConfig(body);
      if (request.method === 'POST' && path === '/api/admin/coach/chatgpt/start') return this.startSignIn(user, body);
      if (request.method === 'POST' && path === '/api/admin/coach/chatgpt/finish') return this.finishSignIn(user, body);
      if (request.method === 'POST' && path === '/api/admin/coach/connect') {
        if (body.type !== 'apikey' || typeof body.token !== 'string' || !body.token.trim() || body.token.length > 8192) throw new HttpError(400, 'an API key is required');
        const cfg = this.config();
        const provider = body.provider ?? cfg.provider;
        if (typeof provider !== 'string' || !Object.hasOwn(HTTP_PROVIDERS, provider)) throw new HttpError(400, 'Use Continue with ChatGPT to connect a plan. Claude requires an Anthropic API key on Workers.');
        const token = body.token.trim();
        if (/[\s\u0000-\u001f\u007f]/.test(token)) throw new HttpError(400, 'invalid API key');
        if (provider === 'anthropic' && /^sk-ant-oat/i.test(token)) throw new HttpError(400, 'Enter an Anthropic API key. Claude subscription tokens require the Claude Code runtime.');
        const data = await this.encrypt({ token }, provider);
        this.assertUser(user, true);
        const current = this.config();
        if ((current.revision || 0) !== (cfg.revision || 0)) throw new HttpError(409, FAILURES.off);
        this.store.put(CONFIG, { ...current, revision: (current.revision || 0) + 1,
          auth: { ...current.auth, [provider]: { id: crypto.randomUUID(), type: 'apikey', account: typeof body.account === 'string' ? body.account.slice(0, 120) : null, data, connectedAt: new Date().toISOString() } } });
        this.store.delete(PENDING);
        return json({ ok: true });
      }
      if (request.method === 'POST' && path === '/api/admin/coach/disconnect') {
        const cfg = this.config();
        const provider = body.provider ?? cfg.provider;
        if (!this.providers()[provider]) throw new HttpError(400, 'unknown provider');
        const rec = cfg.auth[provider];
        const auth = { ...cfg.auth };
        delete auth[provider];
        this.store.put(CONFIG, { ...cfg, revision: (cfg.revision || 0) + 1, auth });
        this.store.delete(PENDING);
        if (provider === 'chatgpt') {
          const cred = await this.decrypt(rec, provider);
          if (cred) await plan.revokeCredential(this.fetchAuth.bind(this), cred);
        }
        this.assertUser(user, true);
        return json({ ok: true });
      }
      if (request.method === 'POST' && path === '/api/admin/coach/models') {
        const cfg = this.config();
        const revision = cfg.revision || 0;
        const check = () => {
          this.assertUser(user, true);
          if ((this.config().revision || 0) !== revision) throw new HttpError(409, FAILURES.off);
        };
        const { adapter, env } = await this.provider(cfg, user.id, check);
        const signal = AbortSignal.timeout(20000);
        const result = await adapter.models(cfg, env, { fetch: this.transport(check, signal), signal });
        check();
        return json(result.ok ? { ok: true, models: result.models } : { ok: false, models: [], error: FAILURES[classifyFailure({ text: result.error })] || FAILURES.internal });
      }
      if (request.method === 'POST' && path === '/api/admin/coach/test') {
        await this.schedule();
        const cfg = this.guard(user);
        const current = this.assertUser(user, true);
        if (this.store.list(JOBS).some(row => row.value.uid === user.id)) throw new HttpError(409, 'A Coach job is already queued for this profile.', 'busy');
        const job = { id: crypto.randomUUID(), uid: user.id, sv: current.sv, sessionKey: user._sessionKey, kind: 'test', revision: cfg.revision || 0, state: 'queued', startedAt: Date.now() };
        this.store.transaction(() => {
          this.store.put(JOBS + job.id, job);
          this.store.put('coach:test:' + user.id, { id: job.id, pending: true });
        });
        return json({ pending: true, job: { id: job.id } }, 202);
      }
      if (request.method === 'GET' && path === '/api/admin/coach/test') {
        const result = this.store.get('coach:test:' + user.id);
        if (!result || result.id !== url.searchParams.get('id')) throw new HttpError(404, 'This test was cancelled. Start it again.');
        return json(result);
      }
      if (request.method === 'POST' && path === '/api/admin/coach/discover') return json({ found: [] });
      return null;
    }
    if (request.method === 'POST' && path === '/api/coach/forget') {
      this.aborts.get(user.id)?.abort();
      this.store.transaction(() => {
        for (const { key, value } of this.store.list(JOBS)) if (value.uid === user.id) this.store.delete(key);
        const rec = this.record(user.id);
        this.store.put('coach:user:' + user.id, { daily: rec.daily, current: null, pending: null, history: [] });
        this.store.delete('coach:test:' + user.id);
      });
      return json({ ok: true });
    }
    const cfg = this.config();
    if (request.method === 'GET' && path === '/api/coach/disclosure') {
      const meta = this.providers()[cfg.provider];
      const base = cfg.provider === 'chatgpt' ? plan.RESOURCE : baseUrlFor(cfg.provider, cfg);
      return json({ provider: cfg.provider, providerLabel: meta?.label, host: base ? new URL(base).host : null, categories: payloadLib.DATA_CATEGORIES, version: 1 });
    }
    if (request.method === 'GET' && path === '/api/coach/account') {
      const connected = this.connected(user.id, cfg);
      return json({ mode: 'instance', provider: cfg.provider, providerLabel: this.providers()[cfg.provider]?.label,
        connected, account: connected ? cfg.auth[cfg.provider]?.account || null : null,
        reason: connected ? null : this.connected(null, cfg) ? 'shared-account' : 'missing', message: connected ? null : this.connected(null, cfg) ? SHARED : 'No provider account connected.' });
    }
    this.guard(user);
    if (request.method === 'GET' && path === '/api/coach/status') return json(this.status(user.id, cfg));
    const kinds = { plan: 'create', review: 'review', debrief: 'debrief', ask: 'ask', adapt: 'adapt' };
    const action = path.slice('/api/coach/'.length);
    if (request.method === 'POST' && Object.hasOwn(kinds, action)) return this.enqueue(user, body, kinds[action]);
    if (request.method === 'POST' && path === '/api/coach/pending/resolve') {
      const rec = this.record(user.id);
      if (rec.pending) {
        const entry = { id: rec.pending.id, kind: rec.pending.kind, outcome: body.dismissed ? 'dismissed' : 'applied',
          accepted: Array.isArray(body.accepted) ? body.accepted.length : 0, rejected: Array.isArray(body.rejected) ? body.rejected.length : 0, at: Date.now() };
        this.store.put('coach:user:' + user.id, { ...rec,
          pending: rec.pending.kind === 'ask' || rec.pending.kind === 'adapt' ? waitingProposal(rec.pending.prev) : null,
          history: [...rec.history, entry].slice(-40) });
      }
      return json({ ok: true });
    }
    if (request.method === 'GET' && path === '/api/coach/cohort') return json({ ok: false, enabled: false });
    if (request.method === 'POST' && path === '/api/coach/cohort/share') return json({ ok: true, sharing: false });
    return null;
  }
}

import webpush from 'web-push';
import { Buffer } from 'node:buffer';
import { createHash, timingSafeEqual, ECDH } from 'node:crypto';
import { restTimerPush, testPush, cleanNext } from '../api/push-messages.js';
import { json, readJson, HttpError } from './http.js';

function authenticated(store, user) {
  const current = user && store.get('users', []).find(u => u.id === user.id);
  const session = user?._sessionKey && store.get(user._sessionKey);
  if (!current || current.disabled || !session || session.uid !== user.id ||
      session.exp <= Date.now() || session.sv !== current.sv || session.sv !== user.sv) {
    throw new HttpError(401, 'not signed in');
  }
  return current;
}

// Worker fetch has no DNS lookup hook. Restrict outbound requests to browser push providers
// instead of accepting arbitrary hosts whose DNS could change after subscription validation.
function validEndpoint(endpoint) {
  if (typeof endpoint !== 'string' || endpoint.length > 2048) return false;
  let url;
  try { url = new URL(endpoint); } catch { return false; }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || (url.port && url.port !== '443')) return false;
  const host = url.hostname;
  return host === 'fcm.googleapis.com' || host === 'updates.push.services.mozilla.com' ||
    host.endsWith('.push.services.mozilla.com') || host === 'web.push.apple.com' ||
    host.endsWith('.notify.windows.com');
}

function subscriptionKeys(keys) {
  const out = {};
  for (const name of ['p256dh', 'auth']) {
    const value = keys?.[name];
    if (typeof value !== 'string' || value.length > 256 || !/^[A-Za-z0-9_\-+/]+={0,2}$/.test(value)) {
      throw new HttpError(400, 'invalid subscription keys');
    }
    const bytes = Buffer.from(value, 'base64url');
    if (bytes.length !== (name === 'p256dh' ? 65 : 16)) throw new HttpError(400, 'invalid subscription keys');
    out[name] = bytes.toString('base64url');
  }
  try { ECDH.convertKey(Buffer.from(out.p256dh, 'base64url'), 'prime256v1'); }
  catch { throw new HttpError(400, 'invalid subscription keys'); }
  return out;
}

function deviceIdOf(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{8,64}$/.test(value) ? value : undefined;
}

function throttle(store, uid, action, max, windowMs) {
  const key = `push:rate:${uid}:${action}`;
  const now = Date.now();
  const previous = store.get(key);
  const rate = previous?.until > now ? previous : { until: now + windowMs, count: 0 };
  if (rate.count >= max) {
    const retryAfter = Math.ceil((rate.until - now) / 1000);
    return json({ error: 'too many requests, try again later', code: 'locked', retryAfter }, 429, { 'retry-after': String(retryAfter) });
  }
  store.put(key, { ...rate, count: rate.count + 1 });
  return null;
}

export class Push {
  constructor(store, env, ctx) {
    this.store = store;
    this.env = env;
    this.ctx = ctx;
  }

  vapid() {
    return this.store.transaction(() => {
      let keys = this.store.get('push:vapid');
      if (!keys) {
        keys = webpush.generateVAPIDKeys();
        this.store.put('push:vapid', keys);
      }
      return { ...keys, subject: this.env.VAPID_SUBJECT || this.env.ORIGIN };
    });
  }

  async schedule() {
    const timers = this.store.get('push:timers', []);
    if (!timers.length) return;
    const due = timers.reduce((at, timer) => Math.min(at, timer.due), Infinity);
    await this.env.PUSH_TIMERS.get(this.env.PUSH_TIMERS.idFromName('personal')).schedule(due);
  }

  // Public for other server subsystems. Recheck both the account and the exact subscription
  // before every send; account deletion or moving a browser to another account revokes it.
  async send(uid, payload, deviceId, guard) {
    const user = this.store.get('users', []).find(u => u.id === uid);
    if (!user || user.disabled) return;
    const subs = this.store.get('push:subscriptions', []).filter(s => s.userId === uid && (!deviceId || !s.deviceId || s.deviceId === deviceId));
    if (!subs.length) return;
    const vapid = this.vapid();
    const body = JSON.stringify(payload);
    let next = 0;
    const worker = async () => {
      while (next < subs.length) {
        const sub = subs[next++];
        const account = this.store.get('users', []).find(u => u.id === uid);
        if (!account || account.disabled || account.sv !== user.sv || (guard && !guard())) return;
        if (!this.store.get('push:subscriptions', []).some(s => s.id === sub.id && s.userId === uid)) continue;
        if (!validEndpoint(sub.endpoint)) {
          this.store.put('push:subscriptions', this.store.get('push:subscriptions', []).filter(s => s.id !== sub.id));
          continue;
        }
        try {
          // generateRequestDetails performs the existing library's encryption and VAPID
          // signing; fetch avoids its Node HTTPS transport, agents and redirect behavior.
          const details = webpush.generateRequestDetails(sub, body, { vapidDetails: vapid, urgency: 'high' });
          const response = await fetch(sub.endpoint, {
            method: details.method, headers: details.headers, body: details.body,
            redirect: 'manual', signal: AbortSignal.timeout(10000),
          });
          await response.body?.cancel();
          if ([403, 404, 410].includes(response.status)) {
            this.store.put('push:subscriptions', this.store.get('push:subscriptions', []).filter(s => s.id !== sub.id));
          } else if (!response.ok) console.error('push delivery refused', response.status);
        } catch (error) {
          // Push services may be unreachable; failed delivery does not revoke a subscription.
          console.error('push delivery failed', error.name);
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(6, subs.length) }, worker));
  }

  async handle(request, user) {
    const url = new URL(request.url);
    const route = `${request.method} ${url.pathname}`;
    if (route === 'GET /api/push/public-key') return json({ key: this.vapid().publicKey });
    if (![
      'GET /api/push/status', 'POST /api/push/subscribe', 'POST /api/push/unsubscribe',
      'POST /api/push/test', 'POST /api/push/rest-timer', 'POST /api/push/rest-timer/cancel',
    ].includes(route)) return null;
    authenticated(this.store, user);
    if (route === 'GET /api/push/status') {
      const endpoint = url.searchParams.get('endpoint') || '';
      const row = this.store.get('push:subscriptions', []).find(s => s.userId === user.id && s.endpoint === endpoint);
      return json(row ? { subscribed: true, deviceId: row.deviceId || null } : { subscribed: false });
    }
    const body = await readJson(request);
    authenticated(this.store, user);
    if (route === 'POST /api/push/subscribe') {
      const sub = body.subscription;
      if (!validEndpoint(sub?.endpoint)) throw new HttpError(400, 'invalid or unsupported push endpoint');
      const keys = subscriptionKeys(sub.keys);
      const deviceId = deviceIdOf(body.deviceId);
      return this.store.transaction(() => {
        const subs = this.store.get('push:subscriptions', []);
        const previous = subs.find(s => s.endpoint === sub.endpoint);
        if (previous && previous.userId !== user.id) {
          const oldDigest = createHash('sha256').update(`${previous.keys?.p256dh}\n${previous.keys?.auth}`).digest();
          const newDigest = createHash('sha256').update(`${keys.p256dh}\n${keys.auth}`).digest();
          if (!timingSafeEqual(oldDigest, newDigest)) throw new HttpError(409, 'this subscription belongs to another account');
        }
        let keep = subs.filter(s => s.endpoint !== sub.endpoint);
        const mine = keep.filter(s => s.userId === user.id);
        const drop = new Set(mine.slice(0, Math.max(0, mine.length - 19)).map(s => s.id));
        keep = keep.filter(s => !drop.has(s.id));
        keep.push({ id: crypto.randomUUID(), userId: user.id, endpoint: sub.endpoint, keys,
          ...(deviceId || previous?.deviceId ? { deviceId: deviceId || previous.deviceId } : {}),
          created: previous?.created || new Date().toISOString() });
        this.store.put('push:subscriptions', keep);
        return json({ ok: true });
      });
    }
    if (route === 'POST /api/push/unsubscribe') {
      this.store.put('push:subscriptions', this.store.get('push:subscriptions', []).filter(s => !(s.userId === user.id && s.endpoint === body.endpoint)));
      return json({ ok: true });
    }
    if (route === 'POST /api/push/test') {
      const limited = throttle(this.store, user.id, 'test', 10, 600000);
      if (limited) return limited;
      await this.send(user.id, testPush(this.store.get('state:' + user.id)?.lang), undefined, () => {
        authenticated(this.store, user);
        return true;
      });
      authenticated(this.store, user);
      return json({ ok: true });
    }
    const deviceId = deviceIdOf(body.deviceId);
    if (route === 'POST /api/push/rest-timer/cancel') {
      this.store.put('push:timers', this.store.get('push:timers', []).filter(t => !(t.uid === user.id && (!deviceId || t.deviceId === deviceId))));
      return json({ ok: true });
    }
    const limited = throttle(this.store, user.id, 'timer', 60, 60000);
    if (limited) return limited;
    const seconds = typeof body.seconds === 'string' || typeof body.seconds === 'number' ? Number(body.seconds) : NaN;
    if (!Number.isFinite(seconds) || seconds < 1) throw new HttpError(400, 'seconds required');
    this.store.transaction(() => {
      let timers = this.store.get('push:timers', []).filter(t => !(t.uid === user.id && t.deviceId === deviceId));
      const mine = timers.filter(t => t.uid === user.id);
      const drop = new Set(mine.slice(0, Math.max(0, mine.length - 4)).map(t => t.id));
      timers = timers.filter(t => !drop.has(t.id));
      timers.push({ id: crypto.randomUUID(), uid: user.id, sv: user.sv, deviceId,
        due: Date.now() + Math.min(3600, Math.round(seconds)) * 1000,
        lang: this.store.get('state:' + user.id)?.lang, next: cleanNext(body.next) });
      this.store.put('push:timers', timers);
    });
    await this.schedule();
    authenticated(this.store, user);
    return json({ ok: true });
  }

  async alarm() {
    // Two timers × twenty subscriptions leaves room under the free Worker's 50-subrequest
    // limit for bookkeeping in the alarm invocation.
    const due = this.store.get('push:timers', []).filter(t => t.due <= Date.now()).slice(0, 2);
    try {
      for (const timer of due) {
        const valid = () => {
          const user = this.store.get('users', []).find(u => u.id === timer.uid);
          return user && !user.disabled && user.sv === timer.sv && this.store.get('push:timers', []).some(t => t.id === timer.id);
        };
        if (valid()) await this.send(timer.uid, restTimerPush(timer.lang, timer.next), timer.deviceId, valid);
        this.store.put('push:timers', this.store.get('push:timers', []).filter(t => t.id !== timer.id));
      }
    } finally {
      await this.schedule();
    }
  }
}

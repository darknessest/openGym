import { createHash } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { HASH_RE, MEDIA_TYPES, sniffMedia, referencedHashes } from '../api/media.js';
import { json, readJson, HttpError } from './http.js';
import { scheduleAlarm } from './alarms.js';

const MB = 1024 * 1024;
const HOUR = 3600000;
export const mediaConfig = {
  imageMB: 2, gifMB: 8, videoMB: 20, videoSec: 60, audioMB: 2, quotaMB: 200,
  workouts: true, days: true, sets: true, sounds: true, avatar: true, builtin: true,
};

function authenticated(store, request, user) {
  const current = user && store.get('users', []).find(u => u.id === user.id);
  const session = user?._sessionKey && store.get(user._sessionKey);
  if (!current || current.disabled || !session || session.uid !== user.id ||
      session.exp <= Date.now() || session.sv !== current.sv || session.sv !== user.sv) {
    throw new HttpError(401, 'not signed in');
  }
  const account = request.headers.get('x-opengym-account');
  if (account && account !== String(user.id)) {
    throw new HttpError(409, 'signed in as another account now', 'account-mismatch');
  }
}

function usage(index) {
  const files = Object.values(index);
  return { bytes: files.reduce((n, f) => n + f.size, 0), count: files.length, quotaBytes: mediaConfig.quotaMB * MB };
}

function throttle(store, uid, action, max) {
  const key = `media:rate:${uid}:${action}`;
  const now = Date.now();
  const previous = store.get(key);
  const rate = previous?.until > now ? previous : { until: now + HOUR, count: 0 };
  if (rate.count >= max) {
    const retryAfter = Math.ceil((rate.until - now) / 1000);
    return json({ error: 'too many uploads, try again later', code: 'locked', retryAfter }, 429, { 'retry-after': String(retryAfter) });
  }
  store.put(key, { ...rate, count: rate.count + 1 });
  return null;
}

// Each pending write owns a unique R2 key, so a failed/stale request can only delete its own
// bytes. Published objects are immutable; the durable index decides which key is visible.
async function cleanPending(store, env) {
  const stale = store.get('media:uploads', []).filter(r => r.expires <= Date.now());
  const garbage = store.get('media:cleanup', []);
  for (const key of [...new Set([...stale.map(r => r.key), ...garbage])].slice(0, 20)) {
    await env.MEDIA.delete(key);
    store.transaction(() => {
      store.put('media:uploads', store.get('media:uploads', []).filter(r => r.key !== key));
      store.put('media:cleanup', store.get('media:cleanup', []).filter(k => k !== key));
    });
  }
}

export function noteMediaState(store, uid, state) {
  const index = store.get('media:' + uid, {});
  const kept = referencedHashes(state);
  for (const [hash, row] of Object.entries(index)) {
    if (kept.has(hash)) delete row.unreferencedSince;
    else row.unreferencedSince ??= Date.now();
  }
  store.put('media:' + uid, index);
}

export async function scheduleMedia(store, ctx) {
  const due = store.get('media:uploads', []).map(row => row.expires);
  if (store.get('media:cleanup', []).length) due.push(Date.now() + 1000);
  for (const user of store.get('users', [])) {
    for (const row of Object.values(store.get('media:' + user.id, {}))) {
      if (row.unreferencedSince != null) due.push(row.unreferencedSince + 14 * 86400000);
    }
  }
  if (due.length) await scheduleAlarm(ctx, Math.max(Date.now() + 1000, Math.min(...due)));
}

export async function mediaCleanup(store, env, ctx) {
  try {
    store.transaction(() => {
      for (const user of store.get('users', [])) {
        const index = store.get('media:' + user.id, {});
        const kept = referencedHashes(store.get('state:' + user.id));
        const active = new Set(store.get('media:uploads', []).filter(row => row.uid === user.id).map(row => row.hash));
        for (const [hash, row] of Object.entries(index)) {
          if (!kept.has(hash) && !active.has(hash) && row.unreferencedSince != null && row.unreferencedSince + 14 * 86400000 <= Date.now()) {
            delete index[hash];
            store.put('media:cleanup', [...store.get('media:cleanup', []), row.key]);
          }
        }
        store.put('media:' + user.id, index);
      }
    });
    await cleanPending(store, env);
  } finally { await scheduleMedia(store, ctx); }
}

// The API's filesystem MP4 reader cannot read an R2 object. Walk the same bounded box headers
// in the already buffered bytes, including mvex/mehd for fragmented Safari recordings.
function videoInfo(bytes) {
  const b = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let count = 0;
  const box = (pos, end) => {
    if (++count > 10000 || end - pos < 8) return null;
    let size = b.readUInt32BE(pos), header = 8;
    if (size === 1) {
      if (end - pos < 16) return null;
      const wide = b.readBigUInt64BE(pos + 8);
      if (wide > BigInt(Number.MAX_SAFE_INTEGER)) return null;
      size = Number(wide); header = 16;
    } else if (size === 0) size = end - pos;
    if (size < header || size > end - pos) return null;
    return { type: b.toString('latin1', pos + 4, pos + 8), body: pos + header, end: pos + size, size };
  };
  let pos = 0, moov;
  while (pos < b.length) {
    const c = box(pos, b.length);
    if (!c || (pos === 0 && (c.type !== 'ftyp' || c.end - c.body < 4))) return null;
    if (c.type === 'moov') { moov = c; break; }
    pos = c.end;
  }
  if (!moov || moov.size > 8 * MB) return null;
  let timescale = 0, duration = null, fragment = null, sawHeader = false;
  const ticks = (offset, wide) => {
    const n = wide ? b.readBigUInt64BE(offset) : BigInt(b.readUInt32BE(offset));
    if (n === 0n || n === (wide ? 0xffffffffffffffffn : 0xffffffffn)) return null;
    return Number(n);
  };
  for (pos = moov.body; pos < moov.end;) {
    const c = box(pos, moov.end);
    if (!c) return null;
    if (c.type === 'mvhd' && !sawHeader) {
      const wide = b[c.body] === 1;
      if (c.end - c.body < (wide ? 32 : 20) || b[c.body] > 1) return null;
      sawHeader = true;
      timescale = b.readUInt32BE(c.body + (wide ? 20 : 12));
      duration = ticks(c.body + (wide ? 24 : 16), wide);
    } else if (c.type === 'mvex') {
      for (let p = c.body; p < c.end;) {
        const child = box(p, c.end);
        if (!child) return null;
        if (child.type === 'mehd') {
          const wide = b[child.body] === 1;
          if (child.end - child.body < (wide ? 12 : 8) || b[child.body] > 1) return null;
          fragment = ticks(child.body + 4, wide);
        }
        p = child.end;
      }
    }
    pos = c.end;
  }
  return sawHeader && timescale ? { duration: (duration ?? fragment) == null ? null : (duration ?? fragment) / timescale } : null;
}

async function upload(store, env, request, user, hash, ctx) {
  const declared = MEDIA_TYPES[(request.headers.get('content-type') || '').split(';')[0].trim().toLowerCase()];
  if (!declared) throw new HttpError(415, 'that file type is not accepted', 'media-type');
  const maxMB = mediaConfig[`${declared.kind}MB`];
  const cap = maxMB * MB;
  const rawLength = request.headers.get('content-length');
  const length = rawLength == null ? null : Number(rawLength);
  if (length != null && (!/^\d+$/.test(rawLength) || !Number.isSafeInteger(length))) throw new HttpError(400, 'invalid content length', 'bad-request');
  if (length > cap) return json({ error: 'that file is too large', code: 'media-too-large', maxMB }, 413);
  if (!request.body) throw new HttpError(400, 'empty upload', 'bad-request');
  await cleanPending(store, env);
  authenticated(store, request, user);
  const indexKey = 'media:' + user.id;
  const id = crypto.randomUUID();
  const key = `media/${encodeURIComponent(user.id)}/${hash}/${id}`;
  const reservation = store.transaction(() => {
    const inflight = store.get('media:uploads', []);
    // A single Durable Object shares the 128 MiB isolate limit between every account.
    if (inflight.length >= 2 || inflight.some(r => r.uid === user.id && r.hash === hash)) {
      return json({ error: 'too many uploads at once, try again in a moment', code: 'busy', retryAfter: 5 }, 429, { 'retry-after': '5' });
    }
    const index = store.get(indexKey, {});
    const used = usage(index);
    const reserved = Math.max(0, (length ?? cap) - (index[hash]?.size || 0));
    if (used.bytes + inflight.filter(r => r.uid === user.id).reduce((n, r) => n + r.reserved, 0) + reserved > used.quotaBytes) {
      return json({ error: 'your space for photos and videos is full', code: 'media-quota', usedMB: Math.round(used.bytes / MB * 10) / 10, quotaMB: mediaConfig.quotaMB }, 413);
    }
    store.put('media:uploads', [...inflight, { id, key, uid: user.id, hash, reserved, expires: Date.now() + 32 * 60000 }]);
    return null;
  });
  if (reservation) return reservation;
  let attempted = false, committed = false;
  try {
    await scheduleAlarm(ctx, Date.now() + 32 * 60000);
    // Allocate once, capped at 20 MiB, instead of keeping chunks plus a second complete copy.
    const bytes = new Uint8Array(length ?? cap);
    const digest = createHash('sha256');
    let size = 0;
    const reader = request.body.getReader();
    const deadline = Date.now() + 30 * 60000;
    let timeout;
    try {
      for (;;) {
        const expired = new Promise((_, reject) => {
          timeout = setTimeout(() => {
            reject(new HttpError(408, 'the upload stalled', 'timeout'));
            reader.cancel().catch(() => {});
          }, Math.max(0, Math.min(60000, deadline - Date.now())));
        });
        const { done, value } = await Promise.race([reader.read(), expired]);
        clearTimeout(timeout);
        authenticated(store, request, user);
        if (done) break;
        size += value.byteLength;
        if (size > cap) return json({ error: 'that file is too large', code: 'media-too-large', maxMB }, 413);
        if (size > bytes.length) throw new HttpError(400, 'content length mismatch', 'bad-request');
        bytes.set(value, size - value.byteLength);
        digest.update(value);
      }
    } finally {
      clearTimeout(timeout);
      await reader.cancel().catch(() => {});
      reader.releaseLock();
    }
    authenticated(store, request, user);
    if (!size || (length != null && size !== length)) throw new HttpError(400, 'content length mismatch', 'bad-request');
    if (digest.digest('hex') !== hash) throw new HttpError(400, 'the file does not match its name', 'hash-mismatch');
    const sn = sniffMedia(bytes.subarray(0, Math.min(size, 64)));
    if (!sn || sn.category !== declared.category) throw new HttpError(415, 'that file type is not accepted', 'media-type');
    const actualMax = mediaConfig[`${sn.kind}MB`];
    if (size > actualMax * MB) return json({ error: 'that file is too large', code: 'media-too-large', maxMB: actualMax }, 413);
    if (sn.ext === 'mp4' || sn.ext === 'mov') {
      const info = videoInfo(bytes.subarray(0, size));
      if (!info) throw new HttpError(415, 'that video could not be read', 'media-invalid');
      if (info.duration != null && info.duration > mediaConfig.videoSec + 1) {
        return json({ error: 'that video is too long', code: 'media-too-long', maxSec: mediaConfig.videoSec }, 413);
      }
    }
    const previous = store.get(indexKey, {})[hash];
    if (previous) {
      const existing = await env.MEDIA.head(previous.key);
      authenticated(store, request, user);
      if (existing?.size === size && previous.size === size) {
        store.transaction(() => {
          const index = store.get(indexKey, {});
          if (index[hash]?.key === previous.key) {
            const kept = referencedHashes(store.get('state:' + user.id));
            if (kept.has(hash)) delete index[hash].unreferencedSince;
            else index[hash].unreferencedSince = Date.now();
            store.put(indexKey, index);
          }
        });
        return json({ ok: true, hash, mime: previous.mime, size, existed: true });
      }
    }
    attempted = true;
    await env.MEDIA.put(key, bytes.subarray(0, size), { httpMetadata: { contentType: sn.mime }, customMetadata: { hash } });
    store.transaction(() => {
      authenticated(store, request, user);
      if (!store.get('media:uploads', []).some(r => r.id === id && r.expires > Date.now())) {
        throw new HttpError(408, 'the upload stalled', 'timeout');
      }
      const index = store.get(indexKey, {});
      const used = usage(index);
      const others = store.get('media:uploads', []).filter(r => r.id !== id && r.uid === user.id).reduce((n, r) => n + r.reserved, 0);
      if (used.bytes - (index[hash]?.size || 0) + size + others > used.quotaBytes) {
        throw new HttpError(413, 'your space for photos and videos is full', 'media-quota');
      }
      if (index[hash]) store.put('media:cleanup', [...store.get('media:cleanup', []), index[hash].key]);
      index[hash] = { key, size, mime: sn.mime, ext: sn.ext };
      store.put(indexKey, index);
      noteMediaState(store, user.id, store.get('state:' + user.id));
      store.put('media:uploads', store.get('media:uploads', []).filter(r => r.id !== id));
    });
    committed = true;
    return json({ ok: true, hash, mime: sn.mime, size, existed: false }, 201);
  } finally {
    let clean = true;
    if (attempted && !committed) {
      try { await env.MEDIA.delete(key); }
      catch (error) { clean = false; console.error('media cleanup failed', error); }
    }
    store.transaction(() => {
      const pending = store.get('media:uploads', []);
      store.put('media:uploads', clean ? pending.filter(r => r.id !== id) : pending.map(r => r.id === id ? { ...r, expires: 0 } : r));
    });
  }
}

export async function mediaRoutes(store, env, request, user, ctx) {
  const path = new URL(request.url).pathname;
  const match = /^\/api\/media\/([0-9a-f]{64})$/.exec(path);
  const file = match && ['GET', 'PUT'].includes(request.method);
  const missing = path === '/api/media/missing' && request.method === 'POST';
  const sweep = path === '/api/media/sweep' && request.method === 'POST';
  if (!file && !missing && !sweep) return null;
  authenticated(store, request, user);
  if (file && request.method === 'PUT') {
    const limited = throttle(store, user.id, 'upload', 600);
    return limited || upload(store, env, request, user, match[1], ctx);
  }
  const indexKey = 'media:' + user.id;
  if (file) {
    const hash = match[1];
    const row = store.get(indexKey, {})[hash];
    const object = row ? await env.MEDIA.get(row.key) : null;
    try { authenticated(store, request, user); }
    catch (error) { await object?.body?.cancel(); throw error; }
    if (!object || !object.size || object.size !== row.size) {
      await object?.body?.cancel();
      authenticated(store, request, user);
      if (row) store.transaction(() => {
        const index = store.get(indexKey, {});
        if (index[hash]?.key === row.key) {
          delete index[hash]; store.put(indexKey, index);
          store.put('media:cleanup', [...store.get('media:cleanup', []), row.key]);
        }
      });
      throw new HttpError(404, 'no such file', 'media-missing');
    }
    return new Response(object.body, { headers: {
      'content-type': row.mime, 'content-length': String(object.size),
      'cache-control': 'private, no-store', 'x-content-type-options': 'nosniff',
      'content-security-policy': "default-src 'none'; sandbox", 'cross-origin-resource-policy': 'same-origin',
      'content-disposition': `inline; filename="${hash}.${row.ext}"`, 'x-robots-tag': 'noindex',
      'access-control-expose-headers': 'Content-Length',
    } });
  }
  const body = await readJson(request);
  authenticated(store, request, user);
  const index = store.get(indexKey, {});
  if (missing) {
    if (!Array.isArray(body.hashes) || body.hashes.length > 1000 || !body.hashes.every(h => typeof h === 'string' && HASH_RE.test(h))) {
      throw new HttpError(400, 'hashes must be a list of at most 1000 lowercase sha256 hex strings', 'bad-request');
    }
    return json({ missing: [...new Set(body.hashes)].filter(h => !index[h]), usage: usage(index) });
  }
  const limited = throttle(store, user.id, 'sweep', 10);
  if (limited) return limited;
  // An explicit reset sweep releases quota immediately. The transaction removes only this
  // profile's currently unreferenced entries; immutable physical keys are deleted durably.
  store.transaction(() => {
    authenticated(store, request, user);
    const current = store.get(indexKey, {});
    const kept = referencedHashes(store.get('state:' + user.id));
    const active = new Set(store.get('media:uploads', []).filter(row => row.uid === user.id).map(row => row.hash));
    for (const [hash, row] of Object.entries(current)) {
      if (!kept.has(hash) && !active.has(hash)) {
        delete current[hash];
        store.put('media:cleanup', [...store.get('media:cleanup', []), row.key]);
      }
    }
    store.put(indexKey, current);
  });
  await mediaCleanup(store, env, ctx);
  authenticated(store, request, user);
  const after = usage(store.get(indexKey, {}));
  return json({ removed: usage(index).count - after.count, freedBytes: usage(index).bytes - after.bytes, usage: after });
}

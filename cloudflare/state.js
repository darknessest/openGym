import { json, readJson, HttpError } from './http.js';
import { stampPut } from '../api/sync-stamps.js';
import { noteMediaState } from './media.js';

function forClient(state) {
  if (!state) return null;
  const { active, _unstamped, _prior, ...visible } = state;
  return visible;
}

export async function stateRoutes(store, request, user) {
  const path = new URL(request.url).pathname;
  const read = request.method === 'GET' && path === '/api/data';
  const rev = request.method === 'GET' && path === '/api/data/rev';
  const write = request.method === 'PUT' && path === '/api/data';
  if (!read && !rev && !write) return null;
  if (!user) throw new HttpError(401, 'not signed in');
  const body = write ? await readJson(request) : null;
  return store.transaction(() => {
    // readJson yields to other requests, including logout, disable and account deletion.
    const currentUser = store.get('users', []).find(u => u.id === user.id);
    const session = user._sessionKey && store.get(user._sessionKey);
    if (!currentUser || currentUser.disabled || !session || session.uid !== user.id ||
        session.exp <= Date.now() || session.sv !== currentUser.sv || session.sv !== user.sv) {
      throw new HttpError(401, 'not signed in');
    }
    const account = request.headers.get('x-opengym-account');
    if (account && account !== String(user.id)) throw new HttpError(409, 'signed in as another account now', 'account-mismatch');
    const key = 'state:' + user.id;
    const current = store.get(key);
    const currentRev = current?._rev || 0;
    if (rev) return json({ rev: currentRev, ...(current?._wid ? { wid: current._wid } : {}) });
    if (read) return json({ state: forClient(current), rev: currentRev });
    const result = commitState(store, user.id, current, body);
    return json(result.body, result.status);
  });
}

// Call inside the caller's synchronous transaction, after checking its session or scoped token.
export function commitState(store, userId, current, body) {
  const currentRev = current?._rev || 0;
  const next = body?.state;
  if (!next || typeof next !== 'object' ||
      !Object.keys(next).some(k => k !== '_rev' && k !== '_ts')) {
    throw new HttpError(400, 'state required');
  }
  if (Array.isArray(next) || ['workouts', 'routines'].some(k => next[k] != null && !Array.isArray(next[k]))) {
    throw new HttpError(400, 'invalid state');
  }
  for (const k of ['workouts', 'routines']) {
    if (Array.isArray(next[k])) next[k] = next[k].filter(x => x && typeof x === 'object' && !Array.isArray(x));
  }
  if ((body.baseRev != null && body.baseRev !== currentRev) ||
      (body.baseRev != null && typeof body.baseWid === 'string' && current?._wid && body.baseWid !== current._wid)) {
    return { status: 409, body: { error: 'conflict', rev: currentRev, state: forClient(current) } };
  }
  delete next.active;
  if ((Number(current?.resetAt) || 0) > (Number(next.resetAt) || 0)) {
    next.resetAt = current.resetAt;
    if (current.resetIds && typeof current.resetIds === 'object') next.resetIds = current.resetIds;
    else delete next.resetIds;
  }
  const report = {};
  try {
    stampPut(current, next, { overRead: body.baseRev != null && body.baseRev === currentRev, stamped: body.stamped === true, report });
    next._rev = currentRev + (report.changed ? 2 : 1);
    next._wids = [...(Array.isArray(current?._wids) ? current._wids : []), ...(current?._wid ? [current._wid] : [])]
      .filter(x => typeof x === 'string').slice(-50);
    next._wid = crypto.randomUUID();
    // Catch excessive nesting before crossing the storage boundary.
    JSON.stringify(next);
  } catch (error) {
    if (error instanceof RangeError) throw new HttpError(400, 'invalid state');
    throw error;
  }
  store.put('state:' + userId, next);
  noteMediaState(store, userId, next);
  return { status: 200, body: { ok: true, ts: next._ts || null, rev: currentRev + 1, wid: next._wid } };
}

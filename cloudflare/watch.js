import { createHash } from 'node:crypto';
import {
  createWatchCode, takeWatchCode, createWatchLink, findWatchLink, touchWatchLink,
  listWatchLinks, dropWatchLinks, boxOf, putSnapshot, pushEvents, queuedEvents, ackEvents,
} from '../api/watch-relay.js';
import { json, readJson, HttpError } from './http.js';

const ROUTES = new Set([
  'POST /api/watch/pair', 'POST /api/watch/redeem', 'GET /api/watch/links',
  'POST /api/watch/unlink', 'PUT /api/watch/snapshot', 'GET /api/watch/events',
  'POST /api/watch/ack', 'GET /api/watch/box', 'POST /api/watch/box',
]);

export async function watchRoutes(store, request, user) {
  const path = new URL(request.url).pathname;
  const route = request.method + ' ' + path;
  if (!ROUTES.has(route)) return null;
  const body = request.method === 'GET' ? {} : await readJson(request);
  return store.transaction(() => {
    const db = { watchLinks: store.get('watch:links', []) };
    const users = store.get('users', []);
    if (path === '/api/watch/redeem') {
      const ip = createHash('sha256').update(request.headers.get('cf-connecting-ip') || 'local').digest('hex');
      const now = Date.now();
      const previous = store.get('watch:rate:' + ip);
      const rate = previous?.exp > now ? previous : { count: 0, exp: now + 300000 };
      if (rate.count >= 30) throw new HttpError(429, 'too many attempts');
      store.put('watch:rate:' + ip, { ...rate, count: rate.count + 1 });
      const codes = new Map(store.get('watch:codes', []));
      const live = new Map([...codes].filter(([, row]) => users.some(u => u.id === row.userId && !u.disabled && u.sv === row.sv)));
      const uid = takeWatchCode(live, body.code);
      store.put('watch:codes', [...live]);
      const account = users.find(u => u.id === uid);
      if (!account) return json({ error: 'invalid or expired code', code: 'pair-invalid' }, 400);
      const made = createWatchLink(db, uid, account.sv, body.name);
      store.put('watch:links', db.watchLinks);
      return json({ token: made.token, id: made.link.id, name: account.name });
    }
    if (path === '/api/watch/box') {
      const token = request.headers.get('authorization')?.replace(/^Bearer /, '') || '';
      const link = findWatchLink(db, token, uid => {
        const account = users.find(u => u.id === uid);
        return account && !account.disabled ? account.sv : null;
      });
      if (!link) throw new HttpError(401, 'not paired', 'watch-unpaired');
      if (touchWatchLink(link)) store.put('watch:links', db.watchLinks);
      const box = boxOf(store.get('watch:box:' + link.userId));
      if (request.method === 'GET') return json({ json: box.snapshot, at: box.snapAt });
      const accepted = pushEvents(box, body.events);
      store.put('watch:box:' + link.userId, box);
      return json({ accepted, json: box.snapshot, at: box.snapAt });
    }
    const account = user && users.find(u => u.id === user.id);
    const session = user?._sessionKey && store.get(user._sessionKey);
    if (!account || account.disabled || !session || session.exp <= Date.now() || session.uid !== account.id || session.sv !== account.sv) throw new HttpError(401, 'not signed in');
    const uid = account.id;
    if (path === '/api/watch/pair') {
      const codes = new Map(store.get('watch:codes', []));
      const made = createWatchCode(codes, uid);
      for (const row of codes.values()) if (row.userId === uid) row.sv = account.sv;
      store.put('watch:codes', [...codes]);
      return json(made);
    }
    if (path === '/api/watch/unlink') {
      dropWatchLinks(db, uid, body.id || null);
      store.put('watch:links', db.watchLinks);
      if (!listWatchLinks(db, uid).length) store.delete('watch:box:' + uid);
      return json({ ok: true, links: listWatchLinks(db, uid) });
    }
    const links = listWatchLinks(db, uid);
    if (path === '/api/watch/links') return json({ links });
    const box = boxOf(store.get('watch:box:' + uid));
    if (path === '/api/watch/events') return json({ events: links.length ? queuedEvents(box) : [], paired: links.length, seen: links.reduce((at, link) => Math.max(at, link.seen || 0), 0) });
    if (path === '/api/watch/snapshot') {
      if (!links.length) throw new HttpError(409, 'no watch paired', 'no-watch');
      if (!putSnapshot(box, body.json)) throw new HttpError(400, 'not a snapshot');
    } else ackEvents(box, body.ids);
    store.put('watch:box:' + uid, box);
    return json({ ok: true });
  });
}

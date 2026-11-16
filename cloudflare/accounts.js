import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import {
  MAX_PASSKEYS, listPasskeys, addPasskeyRecord, renamePasskeyRecord,
  removePasskeyRecord, passkeyRemovalRefused,
} from '../api/passkeys-store.js';
import { json, readJson, HttpError } from './http.js';
import { cleanupCoachUser } from './coach.js';

const SESSION_MS = 90 * 86400000;
const COOKIE = '__Host-gymsid';
const CLEAR_COOKIE = `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
const encoder = new TextEncoder();
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const ROUTES = new Set([
  'GET /api/me', 'POST /api/register/options', 'POST /api/register/verify',
  'POST /api/login/options', 'POST /api/login/verify', 'POST /api/logout', 'POST /api/logout/all',
  'POST /api/register/password', 'POST /api/login/password', 'POST /api/login/password-reset',
  'GET /api/account/password', 'POST /api/account/password', 'DELETE /api/account/password',
  'POST /api/account/email', 'DELETE /api/account/email', 'POST /api/account/delete',
  'GET /api/account/passkeys', 'POST /api/account/passkeys/options', 'POST /api/account/passkeys/verify',
  'POST /api/account/passkeys/rename', 'DELETE /api/account/passkeys',
  'POST /api/account/device-link', 'POST /api/device-link/options', 'POST /api/device-link/verify',
  'POST /api/pair/create', 'POST /api/pair/redeem',
  'GET /api/admin/users', 'GET /api/admin/user', 'POST /api/admin/user/disable',
  'POST /api/admin/user/delete', 'POST /api/admin/user/role', 'POST /api/admin/owner',
  'POST /api/admin/user/password-reset', 'POST /api/admin/user/recovery',
  'GET /api/admin/invites', 'POST /api/admin/invites/new', 'POST /api/admin/invites/revoke',
  'GET /api/admin/audit', 'POST /api/admin/audit/clear',
]);
const PASSWORD_ROUTES = new Set([
  'POST /api/register/password', 'POST /api/login/password', 'POST /api/login/password-reset',
  'GET /api/account/password', 'POST /api/account/password', 'DELETE /api/account/password',
  'POST /api/account/email', 'DELETE /api/account/email', 'POST /api/admin/user/password-reset',
]);

function fail(status, message, code) {
  const error = new HttpError(status, message);
  if (code) error.code = code;
  throw error;
}

function encode(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decode(value) {
  return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}

function randomCode(length) {
  return Array.from(crypto.getRandomValues(new Uint8Array(length)), b => ALPHABET[b % ALPHABET.length]).join('');
}

function nameKey(value) {
  return (typeof value === 'string' ? value : '').normalize('NFKC').trim().toLowerCase();
}

function emailOf(value) {
  const email = nameKey(value);
  if (email.length > 254 || !/^[^\s@<>()[\]\\,;:"]{1,64}@[^\s@<>()[\]\\,;:"._-][^\s@<>()[\]\\,;:"]*\.[^\s@<>()[\]\\,;:".]{2,}$/u.test(email) || email.includes('..')) {
    fail(400, 'that is not an e-mail address', 'email-invalid');
  }
  return email;
}

const COMMON = new Set(['1234567890', '0987654321', '12345678910', '123456789012', '1234567890123',
  '11111111111', '1111111111', '0000000000', '9999999999', '1q2w3e4r5t', '1q2w3e4r5t6y',
  'q1w2e3r4t5', 'qwertyuiop', 'qwertyuiop[]', 'asdfghjkl;', 'asdfghjkl', 'zxcvbnm,./',
  '1qaz2wsx3edc', 'qazwsxedc123', 'qwerty123456', 'qwertz123456', 'azerty123456', 'password12',
  'password123', 'password1234', 'password12345', 'passw0rd123', 'iloveyou123', 'abcdefghij',
  'abcd123456', 'abc1234567', 'a1b2c3d4e5', 'aaaaaaaaaa', 'princess123', 'football123',
  'baseball123', 'sunshine123', 'superman123', 'welcome123', 'welcome1234', 'letmein123',
  'trustno1234', 'changeme123', 'administrator', 'opengym123', 'opengym1234', 'qwerty1234567',
  '123qweasdzxc', 'zaq12wsxcde3', '1q2w3e4r5t6y7u', 'q1w2e3r4t5y6', '123123123123',
  '1234512345', '123456123456', 'monkey12345', 'dragon12345', 'master12345', 'shadow12345',
  'michael123', 'jennifer123', 'computer123', 'starwars123', 'whatever123', 'freedom1234',
  'pokemon1234', 'liverpool123', 'chelsea1234', 'arsenal1234', 'barcelona123', 'realmadrid123',
  'juventus123', 'hallo12345', 'passwort123', 'passwort1234', 'motdepasse123', 'contrasena123',
  'contraseña123', 'senha123456', 'parola12345', 'haslo123456', 'wachtwoord123', 'salasana123', 'gymgymgym1']);
const STEMS = new Set(['password', 'passwort', 'passw0rd', 'motdepasse', 'contrasena', 'contraseña',
  'senha', 'parola', 'haslo', 'wachtwoord', 'salasana', 'qwerty', 'qwertz', 'azerty', 'qwertyuiop',
  'asdfgh', 'letmein', 'welcome', 'iloveyou', 'admin', 'administrator', 'changeme', 'opengym',
  'gym', 'workout', 'fitness', 'dragon', 'monkey', 'football', 'baseball', 'sunshine', 'princess',
  'superman', 'batman', 'master', 'shadow', 'trustno', 'abc', 'abcdef', 'secret', 'login']);

function passwordPolicy(password, name) {
  const normalized = typeof password === 'string' ? password.normalize('NFKC') : '';
  const length = [...normalized].length;
  if (length < 10) fail(400, 'the password needs at least 10 characters', 'too-short');
  if (length > 256) fail(400, 'the password can have at most 256 characters', 'too-long');
  const low = normalized.toLowerCase();
  const stem = low.replace(/^[^\p{L}]+|[^\p{L}]+$/gu, '');
  const nameNormalized = nameKey(name);
  if (new Set(low).size <= 2 || COMMON.has(low) || STEMS.has(stem) ||
      (nameNormalized.length >= 3 && stem === nameNormalized)) {
    fail(400, 'this password is too easy to guess', 'too-common');
  }
}

async function passwordHash(password, salt = encode(crypto.getRandomValues(new Uint8Array(16)))) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(password.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: decode(salt), iterations: 100000 }, key, 256);
  return { salt, hash: encode(new Uint8Array(bits)) };
}

async function passwordMatches(password, stored) {
  const bounded = typeof password === 'string' && [...password.normalize('NFKC')].length <= 256;
  // Unknown identifiers do the same PBKDF2 work as real accounts.
  const candidate = await passwordHash(bounded ? password : '', stored?.salt || 'AAAAAAAAAAAAAAAAAAAAAA');
  const actual = decode(candidate.hash), expected = decode(stored?.hash || 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
  let diff = actual.length ^ expected.length;
  for (let i = 0; i < actual.length; i++) diff |= actual[i] ^ (expected[i] || 0);
  return bounded && !!stored && diff === 0;
}

function nameTaken(users, value, except) {
  const key = nameKey(value);
  return users.some(u => u.id !== except && ((u.pw || u.pwReset) && nameKey(u.name) === key || u.email === key));
}

export function publicUser(user) {
  return { id: user.id, name: user.name, admin: !!user.admin, owner: !!user.owner };
}

export class Accounts {
  constructor(store, env) {
    if (!env.SESSION_SECRET) throw new Error('SESSION_SECRET is required');
    this.store = store;
    this.env = env;
    this.origin = env.ORIGIN ? new URL(env.ORIGIN).origin : null;
    this.rpID = env.RP_ID || (this.origin ? new URL(this.origin).hostname : null);
    this.passwords = env.PASSWORD_LOGIN === 'true';
  }

  async digest(value) {
    const bytes = await crypto.subtle.digest('SHA-256', encoder.encode(`${this.env.SESSION_SECRET}:${value}`));
    return encode(new Uint8Array(bytes));
  }

  async requestKey(request) {
    const authorization = request.headers.get('authorization') || '';
    if (authorization.startsWith('Bearer ')) {
      const token = authorization.slice(7).trim();
      if (!/^[\w-]{43}$/.test(token)) return { key: null, bearer: true };
      return { key: 'session:' + await this.digest('session:' + token), bearer: true };
    }
    const values = (request.headers.get('cookie') || '').split(';').map(x => x.trim())
      .filter(x => x.startsWith(COOKIE + '=')).map(x => x.slice(COOKIE.length + 1));
    const token = values[0];
    if (!token || values.some(x => x !== token) || !/^[\w-]{43}$/.test(token)) return { key: null, bearer: false };
    return { key: 'session:' + await this.digest('session:' + token), bearer: false };
  }

  session(auth) {
    if (!auth.key) return null;
    const session = this.store.get(auth.key);
    if (!session || session.exp <= Date.now() || (!auth.bearer && session.kind !== 'cookie')) return null;
    const user = this.store.get('users', []).find(u => u.id === session.uid);
    if (!user || user.disabled || user.sv !== session.sv) return null;
    Object.defineProperties(user, {
      _sessionKey: { value: auth.key },
      _sessionKind: { value: session.kind },
    });
    return user;
  }

  async user(request) {
    return this.session(await this.requestKey(request));
  }

  require(auth, uid = null, role = null) {
    const user = this.session(auth);
    if (!user || (uid && uid !== user.id)) fail(401, 'not signed in');
    if (role && !user[role]) fail(403, role === 'owner' ? 'only the owner can do this' : 'admin required');
    return user;
  }

  async ticket() {
    const token = encode(crypto.getRandomValues(new Uint8Array(32)));
    return { token, key: 'session:' + await this.digest('session:' + token) };
  }

  issue(ticket, user, kind = 'cookie') {
    this.store.put(ticket.key, { uid: user.id, sv: user.sv, kind, exp: Date.now() + SESSION_MS });
  }

  signedIn(ticket, user, bearer = false, extra = {}) {
    this.issue(ticket, user, bearer ? 'device' : 'cookie');
    return json({ user: publicUser(user), ...(bearer ? { token: ticket.token } : {}), ...extra }, 200,
      bearer ? {} : { 'Set-Cookie': `${COOKIE}=${ticket.token}; Path=/; Max-Age=${SESSION_MS / 1000}; HttpOnly; Secure; SameSite=Lax` });
  }

  audit(ev, user = null, target = null, ok = true) {
    const id = this.store.get('audit:sequence', 0) + 1;
    this.store.put('audit:sequence', id);
    const now = Date.now();
    const events = this.store.get('audit', []).filter(e => e.ts >= now - 90 * 86400000).slice(-4999);
    events.push({ id, ts: now, ev, ok, ...(user ? { uid: user.id, name: user.name } : {}),
      ...(target ? { tgt: target.id, tname: target.name } : {}) });
    this.store.put('audit', events);
  }

  prune(prefix) {
    for (const { key, value } of this.store.list(prefix)) if (value.exp <= Date.now()) this.store.delete(key);
  }

  rate(key, limit, window) {
    this.prune('rate:');
    const now = Date.now();
    let row = this.store.get('rate:' + key);
    if (!row || row.exp <= now) row = { n: 0, exp: now + window };
    if (row.n >= limit) {
      const seconds = Math.max(1, Math.ceil((row.exp - now) / 1000));
      const error = new HttpError(429, 'slow down a little');
      error.code = 'rate-limited';
      error.retryAfter = seconds;
      throw error;
    }
    row.n++;
    this.store.put('rate:' + key, row);
  }

  challenge(data) {
    this.prune('challenge:');
    const cid = crypto.randomUUID();
    this.store.put('challenge:' + cid, { ...data, exp: Date.now() + 5 * 60000 });
    return cid;
  }

  takeChallenge(cid, kind) {
    if (typeof cid !== 'string' || cid.length > 100) fail(400, 'challenge expired, try again', 'challenge-expired');
    const key = 'challenge:' + cid;
    const challenge = this.store.get(key);
    this.store.delete(key);
    if (!challenge || challenge.kind !== kind || challenge.exp <= Date.now()) fail(400, 'challenge expired, try again', 'challenge-expired');
    return challenge;
  }

  passkeyState(user) {
    const passkeys = listPasskeys({ creds: this.store.get('creds', []) }, user.id);
    return { passkeys, password: this.passwords && !!user.pw,
      lastWayIn: passkeys.length + (this.passwords && user.pw ? 1 : 0) <= 1 };
  }

  async registrationOptions(user) {
    if (!this.origin || !this.rpID) fail(503, 'ORIGIN and RP_ID must be configured for passkeys');
    return generateRegistrationOptions({
      rpName: 'openGym', rpID: this.rpID,
      userID: encoder.encode(user.id), userName: user.name, userDisplayName: user.name,
      attestationType: 'none', authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
      excludeCredentials: this.store.get('creds', []).filter(c => c.userId === user.id)
        .map(c => ({ id: c.id, transports: c.transports })),
    });
  }

  async registration(challenge, body) {
    let result;
    try {
      result = await verifyRegistrationResponse({ response: body.credential, expectedChallenge: challenge.challenge,
        expectedOrigin: this.origin, expectedRPID: this.rpID, requireUserVerification: false });
    } catch {
      fail(400, 'the passkey could not be verified', 'passkey');
    }
    if (!result.verified || !result.registrationInfo) fail(400, 'the passkey could not be verified', 'passkey');
    const credential = result.registrationInfo.credential;
    return { id: credential.id, publicKey: encode(credential.publicKey), counter: credential.counter || 0,
      transports: body.credential?.response?.transports, name: body.name };
  }

  async assertion(body, requiredUid = null) {
    const challenge = this.takeChallenge(body.cid, 'login');
    const credential = this.store.get('creds', []).find(c => c.id === body.credential?.id);
    if (!credential || (requiredUid && credential.userId !== requiredUid)) fail(404, 'unknown passkey, create a profile first', 'unknown-credential');
    const before = this.store.get('users', []).find(u => u.id === credential.userId);
    if (!before || before.disabled) fail(403, 'this account has been disabled', 'disabled');
    let result;
    try {
      result = await verifyAuthenticationResponse({ response: body.credential,
        expectedChallenge: challenge.challenge, expectedOrigin: this.origin, expectedRPID: this.rpID,
        requireUserVerification: false,
        credential: { id: credential.id, publicKey: decode(credential.publicKey), counter: credential.counter, transports: credential.transports },
      });
    } catch {
      fail(400, 'the passkey could not be verified', 'passkey');
    }
    if (!result.verified) fail(400, 'the passkey could not be verified', 'passkey');
    return this.store.transaction(() => {
      const user = this.store.get('users', []).find(u => u.id === credential.userId);
      const creds = this.store.get('creds', []);
      const current = creds.find(c => c.id === credential.id && c.userId === credential.userId);
      // The credential may have been removed or used by another assertion while verification yielded.
      if (challenge.exp <= Date.now() || !user || user.disabled || user.sv !== before.sv || !current ||
          current.publicKey !== credential.publicKey || current.counter !== credential.counter) {
        fail(401, 'the passkey changed, try again', 'passkey');
      }
      current.counter = result.authenticationInfo.newCounter;
      current.lastUsed = new Date().toISOString();
      this.store.put('creds', creds);
      return { uid: user.id, sv: user.sv, credentialId: current.id };
    });
  }

  async prove(auth, body) {
    const user = this.require(auth);
    if (body.cid && body.credential) {
      const proof = await this.assertion(body, user.id);
      this.require(auth, user.id);
      return { ...proof, kind: 'passkey' };
    }
    if (!this.passwords || !user.pw) fail(403, 'confirm with your passkey first', 'passkey-required');
    if (typeof body.current !== 'string' || !body.current) fail(403, 'enter your current password', 'current-required');
    this.rate('password:' + user.id, 5, 60000);
    const pw = JSON.stringify(user.pw);
    const matches = await passwordMatches(body.current, user.pw);
    const current = this.require(auth, user.id);
    if (JSON.stringify(current.pw) !== pw) fail(401, 'not signed in');
    if (!matches) fail(403, 'your current password is not right', 'current-wrong');
    return { uid: current.id, sv: current.sv, pw, kind: 'password' };
  }

  proven(auth, proof) {
    const user = this.require(auth, proof.uid);
    if (user.sv !== proof.sv || (proof.pw && JSON.stringify(user.pw) !== proof.pw) ||
        (proof.credentialId && !this.store.get('creds', []).some(c => c.id === proof.credentialId && c.userId === user.id))) {
      fail(401, 'ownership proof expired, try again');
    }
    return user;
  }

  revoke(user) {
    cleanupCoachUser(this.store, user.id, { owner: true });
    user.sv++;
    for (const prefix of ['session:', 'link:', 'pair:']) {
      for (const { key, value } of this.store.list(prefix)) if (value.uid === user.id) this.store.delete(key);
    }
    for (const { key, value } of this.store.list('challenge:')) if (value.uid === user.id) this.store.delete(key);
  }

  remove(user) {
    this.revoke(user);
    cleanupCoachUser(this.store, user.id, { remove: true, owner: true });
    const remaining = this.store.get('users', []).filter(u => u.id !== user.id);
    this.store.put('users', remaining);
    if (!remaining.length) this.store.delete('owner:claimed');
    this.store.put('creds', this.store.get('creds', []).filter(c => c.userId !== user.id));
    this.store.delete('state:' + user.id);
    this.store.delete('tokens:' + user.id);
    this.store.delete('watch:box:' + user.id);
    this.store.put('watch:links', this.store.get('watch:links', []).filter(row => row.userId !== user.id));
    this.store.put('watch:codes', this.store.get('watch:codes', []).filter(([, row]) => row.userId !== user.id));
    this.store.put('push:subscriptions', this.store.get('push:subscriptions', []).filter(row => row.userId !== user.id));
    this.store.put('push:timers', this.store.get('push:timers', []).filter(row => row.uid !== user.id));
    const media = this.store.get('media:' + user.id, {});
    this.store.put('media:cleanup', [...this.store.get('media:cleanup', []), ...Object.values(media).map(row => row.key)]);
    this.store.delete('media:' + user.id);
    this.store.put('media:uploads', this.store.get('media:uploads', []).map(row => row.uid === user.id ? { ...row, expires: 0 } : row));
  }

  signup(body) {
    const users = this.store.get('users', []);
    const code = typeof body.code === 'string' ? body.code.trim().toUpperCase() : '';
    // The existing signup form uppercases its invite-code field.
    const setup = !!this.env.SETUP_CODE && code === String(this.env.SETUP_CODE).trim().toUpperCase();
    const claim = setup && !users.some(u => u.owner) && !this.store.get('owner:claimed', false);
    if (setup && !claim) fail(403, 'initial owner setup has already been used', 'setup-used');
    const invite = this.store.get('invites', []).find(i => i.code === code && !i.usedBy && !i.revoked && (!i.exp || i.exp > Date.now()));
    if (this.env.INVITE_ONLY === 'true' && !claim && !invite) fail(403, 'a valid invite code is required', 'invite');
    return { claim, code, invite };
  }

  createUser(body, id, name, pw = null) {
    const { claim, invite } = this.signup(body);
    const users = this.store.get('users', []);
    if (pw && nameTaken(users, name)) fail(409, 'another profile already signs in with this name', 'name-taken');
    const email = pw && body.email ? emailOf(body.email) : null;
    if (email && users.some(u => u.email === email || ((u.pw || u.pwReset) && nameKey(u.name) === email))) {
      fail(409, 'another profile already uses this e-mail address', 'email-taken');
    }
    const created = new Date().toISOString();
    const user = { id, name, created, sv: 0, admin: claim, owner: claim,
      ...(pw ? { pw: { ...pw, set: created } } : {}), ...(email ? { email } : {}) };
    if (invite) {
      const invites = this.store.get('invites', []);
      const current = invites.find(i => i.code === invite.code);
      current.usedBy = id;
      current.usedAt = created;
      this.store.put('invites', invites);
      user.invitedBy = invite.code;
    }
    if (claim) this.store.put('owner:claimed', true);
    users.push(user);
    this.store.put('users', users);
    return user;
  }

  saveUser(user) {
    const users = this.store.get('users', []);
    const index = users.findIndex(u => u.id === user.id);
    if (index < 0) fail(401, 'not signed in');
    users[index] = user;
    this.store.put('users', users);
  }

  addPasskey(user, credential, recovery = false) {
    const db = { creds: this.store.get('creds', []) };
    if (recovery && db.creds.filter(c => c.userId === user.id).length >= MAX_PASSKEYS) {
      const oldest = db.creds.filter(c => c.userId === user.id)
        .sort((a, b) => (a.lastUsed || a.created).localeCompare(b.lastUsed || b.created))[0];
      db.creds = db.creds.filter(c => c.id !== oldest.id);
    }
    const result = addPasskeyRecord(db, user.id, credential);
    if (result.error) fail(409, result.error, result.code);
    this.store.put('creds', db.creds);
  }

  async handle(request) {
    const url = new URL(request.url);
    const route = request.method + ' ' + url.pathname;
    if (!ROUTES.has(route) || (PASSWORD_ROUTES.has(route) && !this.passwords)) return null;
    try {
      const body = request.method === 'GET' ? {} : await readJson(request);
      if (!body || typeof body !== 'object' || Array.isArray(body)) fail(400, 'JSON object required');
      const auth = await this.requestKey(request);
      if (request.method !== 'GET' && url.pathname !== '/api/pair/redeem' && !(auth.bearer && this.session(auth))) {
        const origin = request.headers.get('origin');
        if ((origin && origin !== (this.origin || url.origin)) || request.headers.get('sec-fetch-site') === 'cross-site') {
          fail(403, 'request must come from this server', 'origin');
        }
      }
      // Do asynchronous token preparation before reading any record used for an eventual write.
      const ticket = await this.ticket();
      const address = await this.digest('rate:' + (request.headers.get('cf-connecting-ip') || 'unknown'));
      if (request.method !== 'GET') this.rate('address:' + address, 120, 10 * 60000);
      this.prune('session:');
      this.prune('link:');
      this.prune('pair:');
      return await this.route(route, request, url, body, auth, ticket, address);
    } catch (error) {
      if (!(error instanceof HttpError)) throw error;
      this.audit('auth.request.fail', null, null, false);
      return json({ error: error.message, ...(error.code ? { code: error.code } : {}),
        ...(error.retryAfter ? { retryAfter: error.retryAfter } : {}) }, error.status,
      error.retryAfter ? { 'Retry-After': String(error.retryAfter) } : {});
    }
  }

  async route(route, request, url, body, auth, ticket, address) {
    if (route === 'GET /api/me') {
      const user = this.require(auth);
      const session = this.store.get(auth.key);
      if (auth.bearer && session.kind === 'device' && session.exp - Date.now() < SESSION_MS / 2) {
        return this.store.transaction(() => {
          const current = this.require(auth, user.id);
          this.issue(ticket, current, 'device');
          return json({ user: publicUser(current), token: ticket.token });
        });
      }
      return json({ user: publicUser(user) });
    }
    if (route === 'POST /api/logout' || route === 'POST /api/logout/all') {
      return this.store.transaction(() => {
        const user = route.endsWith('/all') ? this.require(auth) : this.session(auth);
        if (user && route.endsWith('/all')) { this.revoke(user); this.saveUser(user); }
        else if (auth.key) {
          this.store.delete(auth.key);
          if (user) cleanupCoachUser(this.store, user.id, { sessionKey: auth.key });
        }
        if (user) this.audit(route.endsWith('/all') ? 'auth.logout.all' : 'auth.logout', user);
        return json({ ok: true }, 200, { 'Set-Cookie': CLEAR_COOKIE });
      });
    }
    if (route === 'POST /api/register/password') {
      const name = typeof body.name === 'string' ? body.name.trim().slice(0, 40) : '';
      if (!name) fail(400, 'name required', 'missing');
      this.signup(body);
      passwordPolicy(body.password, name);
      this.rate('signup:' + address, 10, 10 * 60000);
      const pw = await passwordHash(body.password);
      return this.store.transaction(() => {
        const user = this.createUser(body, crypto.randomUUID(), name, pw);
        this.audit('auth.register.ok', user);
        return this.signedIn(ticket, user);
      });
    }
    if (route === 'POST /api/login/password') {
      const identifier = nameKey(body.identifier ?? body.name ?? body.email).slice(0, 300);
      if (!identifier || typeof body.password !== 'string' || !body.password) fail(400, 'name and password required', 'missing');
      const onlyEmail = body.identifier == null && body.name == null;
      const before = this.store.get('users', []).find(u => u.pw &&
        ((identifier.includes('@') && u.email === identifier) || (!onlyEmail && nameKey(u.name) === identifier)));
      this.rate('password:' + (before?.id || await this.digest('identifier:' + identifier)), 5, 60000);
      const fingerprint = JSON.stringify(before?.pw);
      const matches = await passwordMatches(body.password, before?.pw);
      return this.store.transaction(() => {
        const user = this.store.get('users', []).find(u => u.id === before?.id);
        if (!matches || !user || JSON.stringify(user.pw) !== fingerprint || user.sv !== before.sv ||
            !((identifier.includes('@') && user.email === identifier) || (!onlyEmail && nameKey(user.name) === identifier))) {
          fail(401, 'wrong name or password', 'bad-credentials');
        }
        if (user.disabled) fail(403, 'this account has been disabled', 'disabled');
        this.store.delete('rate:password:' + user.id);
        this.audit('auth.password.ok', user);
        return this.signedIn(ticket, user);
      });
    }
    if (route === 'POST /api/register/options') {
      const name = typeof body.name === 'string' ? body.name.trim().slice(0, 40) : '';
      if (!name) fail(400, 'name required', 'missing');
      this.signup(body);
      this.rate('signup:' + address, 10, 10 * 60000);
      const uid = crypto.randomUUID();
      const options = await this.registrationOptions({ id: uid, name });
      return this.store.transaction(() => {
        this.signup(body);
        const cid = this.challenge({ kind: 'register', challenge: options.challenge, uid, name,
          code: body.code });
        return json({ cid, options });
      });
    }
    if (route === 'POST /api/register/verify') {
      const challenge = this.takeChallenge(body.cid, 'register');
      const credential = await this.registration(challenge, body);
      return this.store.transaction(() => {
        if (challenge.exp <= Date.now()) fail(400, 'challenge expired, try again', 'challenge-expired');
        const user = this.createUser(challenge, challenge.uid, challenge.name);
        this.addPasskey(user, credential);
        this.audit('auth.register.ok', user);
        return this.signedIn(ticket, user);
      });
    }
    if (route === 'POST /api/login/options') {
      if (!this.origin || !this.rpID) fail(503, 'ORIGIN and RP_ID must be configured for passkeys');
      this.rate('assertion:' + address, 30, 5 * 60000);
      const options = await generateAuthenticationOptions({ rpID: this.rpID, userVerification: 'preferred', allowCredentials: [] });
      return json({ cid: this.challenge({ kind: 'login', challenge: options.challenge }), options });
    }
    if (route === 'POST /api/login/verify') {
      const proof = await this.assertion(body);
      return this.store.transaction(() => {
        const user = this.store.get('users', []).find(u => u.id === proof.uid);
        if (!user || user.disabled || user.sv !== proof.sv ||
            !this.store.get('creds', []).some(c => c.id === proof.credentialId && c.userId === user.id)) fail(401, 'not signed in');
        this.audit('auth.login.ok', user);
        return this.signedIn(ticket, user);
      });
    }
    if (route === 'POST /api/pair/redeem') {
      const hash = await this.digest('pair:' + nameKey(body.code).replace(/[^a-z0-9]/g, ''));
      return this.store.transaction(() => {
        const pair = this.store.get('pair:' + hash);
        if (!pair || pair.exp <= Date.now()) fail(400, 'invalid or expired code', 'pair-invalid');
        const user = this.store.get('users', []).find(u => u.id === pair.uid);
        if (!user || user.disabled || user.sv !== pair.sv) fail(400, 'invalid or expired code', 'pair-invalid');
        this.store.delete('pair:' + hash);
        this.audit('auth.pair.ok', user);
        return this.signedIn(ticket, user, true);
      });
    }
    if (route === 'POST /api/device-link/options' || route === 'POST /api/device-link/verify') {
      return this.deviceLink(route, body, ticket, address);
    }
    if (route === 'POST /api/login/password-reset') return this.resetPassword(body, ticket, address);
    if (url.pathname.startsWith('/api/admin/')) return this.admin(route, url, body, auth);
    return this.account(route, url, body, auth, ticket);
  }

  async account(route, url, body, auth, ticket) {
    const user = this.require(auth);
    if (route === 'GET /api/account/password') {
      return json({ set: !!user.pw, setAt: user.pw?.set || null, passkeys: this.passkeyState(user).passkeys.length,
        name: user.name, nameTaken: nameTaken(this.store.get('users', []), user.name, user.id), email: user.email || null });
    }
    if (route === 'GET /api/account/passkeys') {
      const users = this.store.get('users', []);
      const last = user.admin && users.length > 1 && users.filter(u => u.admin).length <= 1;
      return json({ ...this.passkeyState(user), ...(last ? { deleteBlocked: 'last-admin' } : {}) });
    }
    if (route === 'POST /api/account/passkeys/rename') {
      return this.store.transaction(() => {
        const current = this.require(auth, user.id);
        const db = { creds: this.store.get('creds', []) };
        const result = renamePasskeyRecord(db, current.id, body.id, body.name);
        if (result.error) fail(404, result.error, result.code);
        this.store.put('creds', db.creds);
        return json({ ok: true, ...this.passkeyState(current) });
      });
    }
    if (route === 'POST /api/account/passkeys/verify') {
      const challenge = this.takeChallenge(body.cid, 'add');
      if (challenge.uid !== user.id) fail(400, 'challenge expired, try again', 'challenge-expired');
      const credential = await this.registration(challenge, body);
      return this.store.transaction(() => {
        const current = this.proven(auth, challenge.proof);
        if (challenge.exp <= Date.now()) fail(400, 'challenge expired, try again', 'challenge-expired');
        this.addPasskey(current, credential);
        this.audit('auth.passkey.add', current);
        return json({ ok: true, ...this.passkeyState(current) });
      });
    }
    if (route === 'POST /api/account/passkeys/options') {
      if (this.passkeyState(user).passkeys.length >= MAX_PASSKEYS) fail(409, 'a profile can have at most 20 passkeys', 'passkey-limit');
      const proof = await this.prove(auth, body);
      const options = await this.registrationOptions(this.proven(auth, proof));
      return this.store.transaction(() => {
        const current = this.proven(auth, proof);
        if (this.passkeyState(current).passkeys.length >= MAX_PASSKEYS) fail(409, 'a profile can have at most 20 passkeys', 'passkey-limit');
        return json({ cid: this.challenge({ kind: 'add', challenge: options.challenge, uid: current.id, proof }), options });
      });
    }
    if (route === 'POST /api/account/device-link' || route === 'POST /api/pair/create') {
      const isPair = route === 'POST /api/pair/create';
      if (!isPair && this.passkeyState(user).passkeys.length >= MAX_PASSKEYS) fail(409, 'a profile can have at most 20 passkeys', 'passkey-limit');
      const proof = await this.prove(auth, body);
      const raw = randomCode(isPair ? 8 : 12);
      const code = isPair ? raw : `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8)}`;
      const prefix = isPair ? 'pair:' : 'link:';
      const hash = await this.digest(prefix + nameKey(raw));
      return this.store.transaction(() => {
        const current = this.proven(auth, proof);
        if (!isPair && this.passkeyState(current).passkeys.length >= MAX_PASSKEYS) fail(409, 'a profile can have at most 20 passkeys', 'passkey-limit');
        for (const { key, value } of this.store.list(prefix)) if (value.uid === current.id) this.store.delete(key);
        const exp = Date.now() + (isPair ? 5 : 10) * 60000;
        this.store.put(prefix + hash, { uid: current.id, sv: current.sv, exp });
        this.audit(isPair ? 'auth.pair.create' : 'auth.link.create', current);
        return json({ code, ...(isPair ? {} : { expires: exp }) });
      });
    }
    if (route === 'POST /api/account/delete') {
      if (typeof body.name !== 'string' || body.name.trim() !== user.name) fail(400, 'type the account name to confirm', 'confirm-name');
      const proof = auth.bearer && user._sessionKind === 'device' && !(this.passwords && user.pw)
        ? { uid: user.id, sv: user.sv, kind: 'device' } : await this.prove(auth, body);
      return this.store.transaction(() => {
        const current = this.proven(auth, proof);
        if (body.name.trim() !== current.name) fail(400, 'type the account name to confirm', 'confirm-name');
        const users = this.store.get('users', []);
        if (current.owner && users.length > 1) {
          fail(409, 'hand ownership to another admin before deleting your profile', 'owner-handover');
        }
        if (current.admin && users.length > 1 && users.filter(u => u.admin).length <= 1) {
          fail(409, 'the last admin cannot leave while other profiles remain', 'last-admin');
        }
        this.remove(current);
        this.audit('auth.account.delete', current);
        return json({ ok: true }, 200, { 'Set-Cookie': CLEAR_COOKIE });
      });
    }
    if (route === 'POST /api/account/password') {
      passwordPolicy(body.next, user.name);
      const proof = await this.prove(auth, body);
      const pw = await passwordHash(body.next);
      return this.store.transaction(() => {
        const current = this.proven(auth, proof);
        if (nameTaken(this.store.get('users', []), current.name, current.id)) {
          fail(409, 'another profile already signs in with this name', 'name-taken');
        }
        this.revoke(current);
        current.pw = { ...pw, set: new Date().toISOString() };
        delete current.pwReset;
        this.saveUser(current);
        this.store.delete('rate:password:' + current.id);
        this.audit('auth.password.change', current);
        // Preserve the caller's session type; a cookie replayed as a bearer stays a cookie session.
        this.issue(ticket, current, user._sessionKind);
        return json({ ok: true, ...(auth.bearer ? { token: ticket.token } : {}) }, 200,
          auth.bearer ? {} : { 'Set-Cookie': `${COOKIE}=${ticket.token}; Path=/; Max-Age=${SESSION_MS / 1000}; HttpOnly; Secure; SameSite=Lax` });
      });
    }
    if (route === 'DELETE /api/account/password') {
      if (!user.pw) return json({ ok: true });
      if (!this.passkeyState(user).passkeys.length) fail(409, 'the password is the only way into this profile', 'last-way-in');
      const proof = await this.prove(auth, body);
      return this.store.transaction(() => {
        const current = this.proven(auth, proof);
        if (!this.passkeyState(current).passkeys.length) fail(409, 'the password is the only way into this profile', 'last-way-in');
        delete current.pw;
        this.saveUser(current);
        this.audit('auth.password.remove', current);
        return json({ ok: true });
      });
    }
    if (route === 'POST /api/account/email' || route === 'DELETE /api/account/email') {
      const email = route.startsWith('DELETE') || body.email == null || body.email === '' ? null : emailOf(body.email);
      if (email === (user.email || null)) return json({ ok: true, email });
      const proof = await this.prove(auth, body);
      return this.store.transaction(() => {
        const current = this.proven(auth, proof);
        if (email && this.store.get('users', []).some(u => u.id !== current.id &&
            (u.email === email || ((u.pw || u.pwReset) && nameKey(u.name) === email)))) {
          fail(409, 'another profile already uses this e-mail address', 'email-taken');
        }
        if (email) current.email = email; else delete current.email;
        this.saveUser(current);
        this.audit(email ? 'auth.email.set' : 'auth.email.remove', current);
        return json({ ok: true, email });
      });
    }
    if (route === 'DELETE /api/account/passkeys') {
      const id = url.searchParams.get('id') || '';
      const refused = passkeyRemovalRefused({ creds: this.store.get('creds', []) }, user.id, id, this.passwords && user.pw ? 1 : 0);
      if (refused) fail(refused.code === 'last-way-in' ? 409 : 404, refused.error, refused.code);
      const proof = await this.prove(auth, body);
      return this.store.transaction(() => {
        const current = this.proven(auth, proof);
        const db = { creds: this.store.get('creds', []) };
        const result = removePasskeyRecord(db, current.id, id, this.passwords && current.pw ? 1 : 0);
        if (result.error) fail(result.code === 'last-way-in' ? 409 : 404, result.error, result.code);
        this.store.put('creds', db.creds);
        for (const { key, value } of this.store.list('link:')) if (value.uid === current.id) this.store.delete(key);
        // A proven, pending registration is a way into the profile too.
        for (const { key, value } of this.store.list('challenge:')) {
          if (value.uid === current.id && value.kind === 'add') this.store.delete(key);
        }
        this.audit('auth.passkey.remove', current);
        return json({ ok: true, ...this.passkeyState(current) });
      });
    }
    return null;
  }

  async deviceLink(route, body, ticket, address) {
    this.rate('link:' + address, 30, 5 * 60000);
    const hash = await this.digest('link:' + nameKey(body.code).replace(/[^a-z0-9]/g, ''));
    const key = 'link:' + hash;
    const link = this.store.get(key);
    const before = link && this.store.get('users', []).find(u => u.id === link.uid);
    if (!link || link.exp <= Date.now() || !before || before.disabled || before.sv !== link.sv) {
      fail(400, 'that code is wrong, used or expired', 'link-invalid');
    }
    if (route.endsWith('/options')) {
      if (link.kind !== 'recovery' && this.passkeyState(before).passkeys.length >= MAX_PASSKEYS) fail(409, 'a profile can have at most 20 passkeys', 'passkey-limit');
      const options = await this.registrationOptions(before);
      return this.store.transaction(() => {
        const current = this.store.get(key);
        const user = this.store.get('users', []).find(u => u.id === link.uid);
        if (!current || current.exp <= Date.now() || !user || user.disabled || user.sv !== link.sv) fail(400, 'that code is wrong, used or expired', 'link-invalid');
        const cid = this.challenge({ kind: 'link', uid: user.id, sv: user.sv, hash, challenge: options.challenge });
        return json({ cid, options, id: user.id, name: user.name, ...(link.kind === 'recovery' ? { recovery: true } : {}) });
      });
    }
    const challenge = this.takeChallenge(body.cid, 'link');
    if (challenge.uid !== link.uid || challenge.sv !== link.sv || challenge.hash !== hash) fail(400, 'challenge expired, try again', 'challenge-expired');
    const credential = await this.registration(challenge, body);
    return this.store.transaction(() => {
      const current = this.store.get(key);
      const user = this.store.get('users', []).find(u => u.id === link.uid);
      if (!current || current.exp <= Date.now() || !user || user.disabled || user.sv !== link.sv || challenge.exp <= Date.now()) {
        fail(400, 'that code is wrong, used or expired', 'link-invalid');
      }
      this.addPasskey(user, credential, current.kind === 'recovery');
      this.store.delete(key);
      this.audit('auth.link.ok', user);
      return this.signedIn(ticket, user);
    });
  }

  async resetPassword(body, ticket, address) {
    this.rate('reset:' + address, 10, 10 * 60000);
    const identifier = nameKey(body.identifier ?? body.name ?? body.email).slice(0, 300);
    const hash = await this.digest('reset:' + nameKey(body.code).replace(/[^a-z0-9]/g, ''));
    const before = this.store.get('users', []).find(u => u.pwReset?.hash === hash &&
      u.pwReset.exp > Date.now() && (nameKey(u.name) === identifier || u.email === identifier));
    if (!before) fail(400, 'that reset code is wrong or has expired', 'reset-invalid');
    if (before.disabled) fail(403, 'this account has been disabled', 'disabled');
    passwordPolicy(body.next, before.name);
    const pw = await passwordHash(body.next);
    return this.store.transaction(() => {
      const user = this.store.get('users', []).find(u => u.id === before.id);
      if (!user || user.disabled || user.sv !== before.sv || user.pwReset?.hash !== hash ||
          user.pwReset.exp <= Date.now() || !(nameKey(user.name) === identifier || user.email === identifier)) {
        fail(400, 'that reset code is wrong or has expired', 'reset-invalid');
      }
      if (nameTaken(this.store.get('users', []), user.name, user.id)) fail(409, 'another profile already signs in with this name', 'name-taken');
      this.revoke(user);
      user.pw = { ...pw, set: new Date().toISOString() };
      delete user.pwReset;
      this.saveUser(user);
      this.store.delete('rate:password:' + user.id);
      this.audit('auth.password.reset', user);
      return this.signedIn(ticket, user);
    });
  }

  async admin(route, url, body, auth) {
    this.require(auth, null, 'admin');
    // Prepare one-time credentials before reading the user/admin records used to authorize them.
    const raw = randomCode(12);
    const code = `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8)}`;
    const isReset = route === 'POST /api/admin/user/password-reset';
    const hash = await this.digest((isReset ? 'reset:' : 'link:') + nameKey(raw));
    return this.store.transaction(() => {
      const ownerOnly = ['POST /api/admin/user/role', 'POST /api/admin/owner', 'POST /api/admin/audit/clear'].includes(route);
      const admin = this.require(auth, null, ownerOnly ? 'owner' : 'admin');
      const users = this.store.get('users', []);
      if (route === 'GET /api/admin/users') {
        return json({ users: users.map(user => {
          const state = this.store.get('state:' + user.id, {});
          return { ...publicUser(user), created: user.created, disabled: !!user.disabled, invitedBy: user.invitedBy || null,
            workouts: Array.isArray(state.workouts) ? state.workouts.length : 0,
            lastSync: state._ts || null, hasPush: false, live: null,
            ...(this.passwords ? { password: !!user.pw, email: user.email || null } : {}) };
        }), invite_only: this.env.INVITE_ONLY === 'true', data_view: false,
        ...(this.passwords ? { password_login: true } : {}), now: Date.now() });
      }
      if (route === 'GET /api/admin/invites') {
        return json({ invites: this.store.get('invites', []).map(i => ({ ...i,
          usedByName: users.find(u => u.id === i.usedBy)?.name || null })), invite_only: this.env.INVITE_ONLY === 'true' });
      }
      if (route === 'POST /api/admin/invites/new') {
        const invites = this.store.get('invites', []);
        const inviteCode = encode(crypto.getRandomValues(new Uint8Array(16))).toUpperCase();
        const invite = { code: inviteCode, note: typeof body.note === 'string' ? body.note.slice(0, 60) : '',
          createdBy: admin.id, created: new Date().toISOString() };
        invites.push(invite);
        this.store.put('invites', invites);
        this.audit('admin.invite.create', admin);
        return json({ invite });
      }
      if (route === 'POST /api/admin/invites/revoke') {
        const invites = this.store.get('invites', []);
        const code = typeof body.code === 'string' ? body.code.trim().toUpperCase() : '';
        const invite = invites.find(i => i.code === code);
        if (!invite) fail(404, 'no such code');
        if (invite.usedBy) fail(400, 'already used, cannot revoke');
        this.store.put('invites', invites.filter(i => i.code !== code));
        this.audit('admin.invite.revoke', admin);
        return json({ ok: true });
      }
      if (route === 'GET /api/admin/audit') {
        const limit = Math.max(1, Math.min(200, Number(url.searchParams.get('limit')) || 100));
        const before = Number(url.searchParams.get('before')) || Infinity;
        const category = url.searchParams.get('cat');
        const events = this.store.get('audit', []).filter(e => e.ts >= Date.now() - 90 * 86400000).reverse()
          .filter(e => !category || (category === 'fail' ? !e.ok : e.ev.startsWith(category + '.')));
        const page = events.filter(e => e.id < before).slice(0, limit);
        return json({ events: page, total: events.length, nextBefore: page.length === limit ? page[page.length - 1].id : null,
          enabled: true, ip_mode: 'off', retention: { max: 5000, days: 90 }, now: Date.now() });
      }
      if (route === 'POST /api/admin/audit/clear') {
        this.store.put('audit', []);
        this.audit('admin.audit.clear', admin);
        return json({ ok: true });
      }
      const id = route === 'GET /api/admin/user' ? url.searchParams.get('id') : body.id;
      const user = users.find(u => u.id === id);
      if (!user) fail(404, 'no such user');
      if (route === 'GET /api/admin/user') {
        const state = this.store.get('state:' + user.id, {});
        const recovery = this.store.list('link:').find(x => x.value.uid === user.id && x.value.kind === 'recovery' && x.value.exp > Date.now());
        return json({ user: { ...publicUser(user), created: user.created, disabled: !!user.disabled, invitedBy: user.invitedBy || null,
          ...(this.passwords ? { password: !!user.pw, email: user.email || null, resetUntil: user.pwReset?.exp > Date.now() ? user.pwReset.exp : null } : {}),
          recoveryUntil: recovery?.value.exp || null },
        unit: state.unit || 'kg', lastSync: state._ts || null, hasPush: false,
        bytes: encoder.encode(JSON.stringify(state)).length, data_view: false,
        counts: Object.fromEntries(['workouts', 'bodyweight', 'measurements', 'routines'].map(k => [k, Array.isArray(state[k]) ? state[k].length : 0])) });
      }
      if (route === 'POST /api/admin/user/disable') {
        if (user.admin) fail(400, 'cannot disable an admin');
        user.disabled = !!body.disabled;
        if (user.disabled) this.revoke(user);
        this.saveUser(user);
        this.audit(user.disabled ? 'admin.user.disable' : 'admin.user.enable', admin, user);
        return json({ ok: true, id: user.id, disabled: user.disabled });
      }
      if (route === 'POST /api/admin/user/delete') {
        if (user.id === admin.id) fail(400, 'you cannot delete your own account');
        if (user.owner) fail(400, 'the owner cannot be deleted; hand the role to another admin first');
        if (user.admin && !admin.owner) fail(403, 'only the owner can delete an admin');
        if (user.admin && users.filter(u => u.admin).length <= 1) fail(400, 'cannot delete the last admin');
        this.remove(user);
        this.audit('admin.user.delete', admin, user);
        return json({ ok: true, id: user.id });
      }
      if (route === 'POST /api/admin/user/role') {
        if (user.id === admin.id || user.owner) fail(400, 'the owner stays an admin');
        if (typeof body.admin !== 'boolean') fail(400, 'admin must be true or false');
        if (body.admin && user.disabled) fail(400, 'enable the account first');
        user.admin = body.admin;
        this.saveUser(user);
        this.audit(body.admin ? 'admin.role.grant' : 'admin.role.revoke', admin, user);
        return json({ ok: true, id: user.id, admin: user.admin });
      }
      if (route === 'POST /api/admin/owner') {
        if (user.id === admin.id) fail(400, 'you already are the owner');
        if (!user.admin || user.disabled) fail(400, 'make them an admin first');
        cleanupCoachUser(this.store, admin.id, { owner: true });
        for (const u of users) u.owner = u.id === user.id;
        this.store.put('users', users);
        this.audit('admin.owner.transfer', admin, user);
        return json({ ok: true, id: user.id });
      }
      if (route === 'POST /api/admin/user/password-reset' || route === 'POST /api/admin/user/recovery') {
        if (isReset && user.admin) fail(400, 'an admin sets their own password in Settings');
        if (!isReset && (user.owner || user.id === admin.id)) fail(403, 'the owner or your own account cannot be recovered here', 'owner');
        if (!isReset && user.admin && !admin.owner) fail(403, 'only the owner can make a recovery code for an admin');
        if (user.disabled) fail(400, 'enable the account first', 'disabled');
        if (isReset && nameTaken(users, user.name, user.id)) fail(409, 'another profile already signs in with this name', 'name-taken');
        this.revoke(user);
        const exp = Date.now() + 86400000;
        if (isReset) {
          delete user.pw;
          user.pwReset = { hash, exp, by: admin.id };
        } else {
          this.store.put('link:' + hash, { uid: user.id, sv: user.sv, exp, kind: 'recovery', by: admin.id });
        }
        this.saveUser(user);
        this.audit(isReset ? 'admin.password.reset' : 'admin.recovery.create', admin, user);
        return json({ ok: true, name: user.name, code, expires: exp });
      }
      return null;
    });
  }
}

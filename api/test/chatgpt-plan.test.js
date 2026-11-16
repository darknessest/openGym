/* ChatGPT plan usage (preview, COACH_CHATGPT_PLAN=on): the sign-in request as OpenAI's open-source
   guide spells it, the ID token and callback contracts, the ID token check, the Responses stream, and the adapter
   renewing its own session. developers.openai.com/siwc/token-sharing-open-source */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { tempData } from './helpers.mjs';

tempData();
process.env.COACH_CHATGPT_PLAN = 'on';
const plan = await import('../coach/chatgpt-plan.js');
const cfgStore = await import('../coach/config.js');
const { default: adapter, sessionFor } = await import('../coach/adapters/chatgpt.js');

test('the ID token is checked against the key set: signature, issuer, audience, nonce, expiry', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256' };
  const sign = (claims, kid = 'k1') => {
    const h = Buffer.from(JSON.stringify({ alg: 'RS256', kid })).toString('base64url');
    const p = Buffer.from(JSON.stringify(claims)).toString('base64url');
    return h + '.' + p + '.' + crypto.sign('RSA-SHA256', Buffer.from(h + '.' + p), privateKey).toString('base64url');
  };
  const good = { iss: 'https://auth.openai.com', aud: 'oaiapp_1', exp: Math.floor(Date.now() / 1000) + 600, nonce: 'n', sub: 's', email: 'a@b.c' };
  const jwks = { keys: [jwk] };
  assert.equal(plan.verifyIdToken(sign(good), jwks, { audience: 'oaiapp_1', nonce: 'n' }).ok, true);
  assert.equal(plan.verifyIdToken(sign({ ...good, aud: 'other' }), jwks, { audience: 'oaiapp_1', nonce: 'n' }).ok, false);
  assert.equal(plan.verifyIdToken(sign({ ...good, iss: 'https://evil' }), jwks, { audience: 'oaiapp_1', nonce: 'n' }).ok, false);
  assert.equal(plan.verifyIdToken(sign({ ...good, nonce: 'x' }), jwks, { audience: 'oaiapp_1', nonce: 'n' }).ok, false);
  assert.equal(plan.verifyIdToken(sign({ ...good, exp: 1 }), jwks, { audience: 'oaiapp_1', nonce: 'n' }).ok, false);
  assert.equal(plan.verifyIdToken(sign(good, 'k2'), jwks, { audience: 'oaiapp_1', nonce: 'n' }).ok, false);
  const forged = sign(good).split('.'); forged[1] = Buffer.from(JSON.stringify({ ...good, email: 'x@y.z' })).toString('base64url');
  assert.equal(plan.verifyIdToken(forged.join('.'), jwks, { audience: 'oaiapp_1', nonce: 'n' }).ok, false);
  assert.equal(plan.planGranted('openid chatgpt.tokens.use.direct'), true);
  assert.equal(plan.planGranted('openid profile'), false);
});

test('the request follows the preview rules, and the stream folds to its text or its usage limit', () => {
  const b = plan.responsesBody({ model: 'm', prompt: 'p', instructions: 'i' });
  assert.equal(b.store, false);
  assert.equal(b.stream, true);
  assert.deepEqual(b.input, [{ role: 'user', content: 'p' }]);
  for (const k of ['max_output_tokens', 'temperature', 'metadata', 'previous_response_id', 'user']) assert.equal(k in b, false, k);
  const ev = (type, extra = {}) => ({ event: type, data: { type, ...extra } });
  assert.deepEqual(plan.foldResponses([ev('response.output_text.delta', { delta: '{"a"' }), ev('response.output_text.delta', { delta: ':1}' }), ev('response.completed')]), { ok: true, text: '{"a":1}' });
  const lim = plan.foldResponses([ev('response.failed', { response: { error: { code: 'subscription_sharing_usage_limit_exceeded' } } })]);
  assert.equal(lim.limit, true);
  assert.match(lim.error, /chatgpt\.com\/settings\/usage/);
  assert.equal(plan.foldResponses([ev('response.output_text.delta', { delta: 'x' })]).ok, false, 'no completed event is not an answer');
});

test('the adapter renews a session about to run out (once, the rotated refresh token kept) and calls Responses', async () => {
  cfgStore.reset();
  assert.ok(cfgStore.PROVIDERS.chatgpt, 'the provider exists with the switch on');
  const cred = { token: 'old-access', refresh: 'r1', exp: Date.now() + 60000, clientId: 'oaiapp_1', hostId: 'h', scope: plan.SCOPE };
  cfgStore.saveAuth('chatgpt', { type: 'oauth', account: 'a@b.c', data: cfgStore.encrypt(cred), connectedAt: new Date().toISOString() });
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push([url, init.method || 'GET', String(init.body || ''), init.headers?.authorization || null]);
    if (url === plan.TOKEN_URL) return new Response(JSON.stringify({ access_token: 'new-access', refresh_token: 'r2', expires_in: 3600, scope: plan.SCOPE }), { status: 200 });
    if (url.endsWith('/models')) return new Response(JSON.stringify({ models: [{ slug: 'gpt-x', visibility: 'list' }, { slug: 'hidden', visibility: 'hide' }] }), { status: 200 });
    if (url.endsWith('/responses')) {
      const sse = ['event: response.output_text.delta', 'data: {"type":"response.output_text.delta","delta":"{\\"ok\\":true}"}', '', 'event: response.completed', 'data: {"type":"response.completed"}', '', ''].join('\n');
      return new Response(sse, { status: 200, headers: { 'content-type': 'text/event-stream' } });
    }
    return new Response('{}', { status: 404 });
  };
  const [a, b] = await Promise.all([sessionFor(fetchImpl), sessionFor(fetchImpl)]);
  assert.equal(a.cred.token, 'new-access');
  assert.equal(b.cred.token, 'new-access');
  assert.equal(calls.filter(c => c[0] === plan.TOKEN_URL).length, 1, 'two jobs, one renewal');
  assert.match(calls[0][2], /grant_type=refresh_token/);
  assert.match(calls[0][2], /resource=https%3A%2F%2Fapi.openai.com%2Fv1/);
  const stored = cfgStore.decrypt(cfgStore.authFor(cfgStore.load(), 'chatgpt').data);
  assert.equal(stored.refresh, 'r2');
  assert.deepEqual((await adapter.models(null, null, { fetch: fetchImpl })).models, ['gpt-x']);
  const r = await adapter.invoke({ prompt: 'hi', model: 'gpt-x', fetch: fetchImpl });
  assert.deepEqual({ code: r.code, text: r.text }, { code: 0, text: '{"ok":true}' });
  const sent = JSON.parse(calls.at(-1)[2]);
  assert.equal(sent.store, false);
  assert.equal(calls.at(-1)[3], 'Bearer new-access');
  assert.equal(cfgStore.isPersonalCredential('oauth'), true, 'it binds to the first profile, like the setup token');
});

import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { buildServer, VERSION } from '../mcp/src/server.js';
import { createRemoteProfile } from '../mcp/src/remote.js';
import { withProfile } from '../mcp/src/state.js';
import { HttpError, json, readJson } from './http.js';

const MAX_BODY = 1024 * 1024;
const BEARER = /^Bearer (ogt_[A-Za-z0-9_-]{43})$/;
const AUTH_HEADERS = { 'WWW-Authenticate': 'Bearer realm="openGym"' };

// The outer Worker owns origin, CORS and admission limits. Every API operation below
// goes directly to the personal Durable Object, carrying the request's scoped token.
export async function mcpRequest(request, env) {
  const path = new URL(request.url).pathname;
  if (path === '/mcp/health') {
    return request.method === 'GET'
      ? json({ ok: true, version: VERSION })
      : json({ error: 'method not allowed' }, 405, { Allow: 'GET' });
  }
  if (path !== '/mcp') return json({ error: 'not found' }, 404);
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405, { Allow: 'POST' });

  const token = BEARER.exec(request.headers.get('authorization') || '')?.[1];
  if (!token) return json({ error: 'an openGym API token is required' }, 401, AUTH_HEADERS);

  let parsedBody;
  try {
    parsedBody = await readJson(request, MAX_BODY);
  } catch (error) {
    const status = error instanceof HttpError && error.status === 413 ? 413 : 400;
    return json({ error: status === 413 ? 'request too large' : 'invalid JSON request' }, status);
  }

  let server;
  let transport;
  // buildServer turns tool exceptions into MCP results. Remember native API failures
  // separately so revocation and rate limits still become HTTP errors on tool calls.
  let apiError;
  try {
    const gym = env.GYM.get(env.GYM.idFromName('personal'));
    const remote = createRemoteProfile({
      base: env.ORIGIN,
      token,
      fetch: async (input, init) => {
        let response;
        try {
          response = await gym.fetch(input, init);
        } catch {
          apiError = json({ error: 'openGym API unavailable' }, 502);
          throw new Error('openGym API unavailable');
        }
        // A conflict carries the current document for the existing write tools to
        // merge. All other failures are sanitized before apiFetch sees their body.
        if (!response.ok && response.status !== 409) {
          if (response.status === 401) {
            apiError = json({ error: 'openGym did not accept this token' }, 401, AUTH_HEADERS);
          } else if (response.status === 429) {
            apiError = json({ error: 'too many requests' }, 429, {
              'Retry-After': response.headers.get('retry-after') || '60',
            });
          } else {
            apiError = json({ error: 'openGym API unavailable' }, 502);
          }
          await response.body?.cancel();
          throw new Error('openGym API request failed');
        }
        return response;
      },
    });
    const me = await remote.me({ fresh: true });
    if (!me.scopes || typeof me.scopes !== 'object' || Array.isArray(me.scopes)) {
      return json({ error: 'openGym API returned invalid token scopes' }, 502);
    }
    server = buildServer({
      scopes: me.scopes,
      around: async fn => {
        await remote.refresh();
        return withProfile(remote.snapshot(), fn);
      },
    });
    transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    await server.connect(transport);
    // In JSON mode the SDK resolves only after serializing the complete response;
    // notifications resolve with 202. Closing in finally cannot truncate a stream.
    const response = await transport.handleRequest(request, { parsedBody });
    if (apiError) {
      await response.body?.cancel();
      return apiError;
    }
    response.headers.set('cache-control', 'no-store');
    return response;
  } catch {
    return apiError || json({ error: 'MCP request failed' }, 502);
  } finally {
    // server.close() closes its connected transport; the second close also covers
    // connect failures, and the native transport makes repeated closes harmless.
    try { await server?.close(); } catch { /* do not replace a completed response */ }
    try { await transport?.close(); } catch { /* do not replace a completed response */ }
  }
}

// Capture before authentication/router boot can replace the Admin route. Credentials never go
// into storage or the request URL; only this page's memory holds the one-use callback.
export const chatgptHandoff = { relay: null, callback: null };

function captureChatgptHandoff() {
  if (typeof window === 'undefined') return
  const address = new URL(window.location.href);
  const route = address.hash.slice(1);
  const queryAt = route.indexOf('?');
  if (queryAt >= 0) {
    const path = route.slice(0, queryAt);
    const params = new URLSearchParams(route.slice(queryAt + 1));
    const keys = ['chatgpt_port', 'chatgpt_relay', 'chatgpt_callback'];
    if (keys.some(key => params.has(key))) {
      const port = params.get('chatgpt_port');
      const relayNonce = params.get('chatgpt_relay');
      const callback = params.get('chatgpt_callback');
      if (path === '/admin' && keys.every(key => params.getAll(key).length <= 1)) {
        if (port && /^[1-9][0-9]{0,4}$/.test(port) && Number(port) <= 65535 &&
            relayNonce && /^[A-Za-z0-9_-]{43}$/.test(relayNonce)) {
          chatgptHandoff.relay = { port: Number(port), relayNonce };
        }
        if (callback && callback.length <= 8192) chatgptHandoff.callback = callback;
      }
      for (const key of keys) params.delete(key);
      const remaining = params.toString();
      address.hash = path + (remaining ? '?' + remaining : '');
      window.history.replaceState(window.history.state, '', address.pathname + address.search + address.hash);
    }
  }
}

captureChatgptHandoff()
if (typeof window !== 'undefined') window.addEventListener('hashchange', captureChatgptHandoff)

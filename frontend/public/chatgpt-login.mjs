#!/usr/bin/env node
// Run on the computer that owns the browser. OAuth credentials stay with openGym's server.
import { randomBytes } from 'node:crypto'
import { createServer } from 'node:http'
import { spawn } from 'node:child_process'

const input = process.argv[2]
let origin
try {
  const url = new URL(input)
  if (process.argv.length !== 3 || !/^https?:\/\/[^/?#\\\s@]+\/?$/i.test(input)
    || url.username || url.password || url.pathname !== '/' || url.search || url.hash
    || (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)))) throw new Error()
  origin = url.origin
} catch {
  console.error('Usage: node chatgpt-login.mjs https://your-opengym.example\nUse an HTTPS origin without a path, credentials, query or fragment. HTTP is allowed only on loopback for local verification.')
  process.exitCode = 1
}

if (origin) {
  const relayNonce = randomBytes(32).toString('base64url')
  let callbackOrigin
  let timeout
  let stopping = false
  let opener
  let openerTimeout
  const stop = (exitCode = 0) => {
    if (stopping) return
    stopping = true
    process.exitCode = exitCode
    clearTimeout(timeout)
    clearTimeout(openerTimeout)
    if (opener && opener.exitCode === null) opener.kill()
    process.removeListener('SIGINT', interrupt)
    process.removeListener('SIGTERM', terminate)
    server.close()
    server.closeAllConnections()
  }
  const interrupt = () => stop(130)
  const terminate = () => stop(143)
  const server = createServer({ maxHeaderSize: 16384, requestTimeout: 10000, headersTimeout: 10000 }, (req, res) => {
    res.setHeader('Cache-Control', 'no-store')
    res.setHeader('Referrer-Policy', 'no-referrer')
    res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Content-Type', 'text/plain; charset=utf-8')
    res.setHeader('Connection', 'close')
    let callback
    try {
      // Accept only origin-form requests for this listener; never trust a supplied URL authority.
      if (stopping || req.method !== 'GET' || !req.url || req.url.length > 8192
        || !req.url.startsWith('/auth/callback?') || /[\s#\\]/.test(req.url)
        || req.headers.host !== callbackOrigin.slice(7)
        || (req.headers.origin !== undefined && req.headers.origin !== callbackOrigin)) throw new Error()
      callback = new URL(callbackOrigin + req.url)
      const query = callback.searchParams
      const state = query.get('state')
      const code = query.get('code')
      const error = query.get('error')
      if (callback.pathname !== '/auth/callback' || query.getAll('state').length !== 1
        || !state?.startsWith(relayNonce + '.') || !/^[A-Za-z0-9_-]+$/.test(state.slice(relayNonce.length + 1))
        || query.getAll('code').length > 1 || query.getAll('error').length > 1
        || (query.has('code') === query.has('error')) || !(code || error)
        || /[\u0000-\u0020\u007f]/.test(code || error)
        || query.getAll('client_id').length > 1) throw new Error()
    } catch {
      res.writeHead(400)
      res.end('This request does not match the active sign-in. Continue in the openGym browser window.')
      return
    }
    // The fragment is never sent to the hosted web server in the navigation request.
    res.writeHead(303, { Location: origin + '/#/admin?chatgpt_callback=' + encodeURIComponent(callback.href) })
    res.once('finish', () => {
      console.log('Callback handed to openGym. Check the browser for the sign-in result.')
      stop()
    })
    res.once('close', () => stop())
    res.end('Returning to openGym…')
  })
  server.on('clientError', (_error, socket) => {
    socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Length: 0\r\n\r\n')
  })
  server.on('error', () => {
    console.error('Could not start the loopback callback listener. Run this helper again on your computer.')
    stop(1)
  })
  process.once('SIGINT', interrupt)
  process.once('SIGTERM', terminate)
  timeout = setTimeout(() => {
    console.error('Sign-in timed out after 15 minutes. Run this helper again to start a new attempt.')
    stop(1)
  }, 15 * 60 * 1000)
  try {
    server.listen(0, '127.0.0.1', () => {
      if (stopping) { server.close(); return }
      callbackOrigin = 'http://127.0.0.1:' + server.address().port
      const hostedUrl = origin + '/#/admin?chatgpt_port=' + server.address().port + '&chatgpt_relay=' + relayNonce
      console.log('Keep this terminal open and continue with ChatGPT in openGym.\nOpen this address in your browser on this computer:\n' + hostedUrl)
      // Always print the address: a missing desktop opener must not break the sign-in.
      const command = process.platform === 'darwin' ? ['open', [hostedUrl]]
        : process.platform === 'linux' ? ['xdg-open', [hostedUrl]]
          : process.platform === 'win32' ? ['rundll32.exe', ['url.dll,FileProtocolHandler', hostedUrl]] : null
      if (command) {
        try {
          opener = spawn(command[0], command[1], { shell: false, stdio: 'ignore', windowsHide: true })
          opener.on('error', () => console.log('Open the printed address in your browser to continue.'))
          opener.on('exit', code => {
            clearTimeout(openerTimeout)
            if (code && !stopping) console.log('Open the printed address in your browser to continue.')
          })
          openerTimeout = setTimeout(() => {
            if (opener.exitCode === null) opener.kill()
          }, 10000)
        } catch {
          console.log('Open the printed address in your browser to continue.')
        }
      }
    })
  } catch {
    console.error('Could not start the loopback callback listener. Run this helper again on your computer.')
    stop(1)
  }
}

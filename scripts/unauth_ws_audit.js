const WebSocket = require(process.env.DSH_WS_MODULE || 'ws')

const host = process.env.DSH_AUDIT_HOST || 'dsh.example.com'
const scheme = (process.env.DSH_AUDIT_SCHEME || 'https').toLowerCase()
const port = process.env.DSH_AUDIT_PORT || (scheme === 'https' ? '443' : '80')
if (!['http', 'https'].includes(scheme)) throw new Error('DSH_AUDIT_SCHEME must be http or https')
const wsScheme = scheme === 'https' ? 'wss' : 'ws'
const authority = (scheme === 'https' && port === '443') || (scheme === 'http' && port === '80') ? host : `${host}:${port}`
const base = `${wsScheme}://${authority}`
const targets = [
  `${base}/api/events.mux`,
  `${base}/api/events.host`,
  `${base}//api/events.mux`,
  `${base}/%2e/api/events.mux`,
  `${base}/api%2fevents.mux`,
  `${base}/API/events.mux`,
]
const headersList = [
  {},
  { Authorization: 'Bearer wrong' },
  { Cookie: 'dsh_gateway_session=wrong' },
  { 'X-Forwarded-For': '127.0.0.1', 'CF-Connecting-IP': '127.0.0.1' },
  { Host: '127.0.0.1:3080' },
]
const failures = []

Promise.all(targets.flatMap(url => headersList.map((headers, idx) => new Promise(resolve => {
  let settled = false
  const finish = failure => {
    if (settled) return
    settled = true
    clearTimeout(timer)
    if (failure) failures.push(failure)
    resolve()
  }
  const ws = new WebSocket(url, { headers: { Origin: `${scheme}://${authority}`, ...headers } })
  const timer = setTimeout(() => {
    try { ws.terminate() } catch {}
    finish([url, idx, 'timeout'])
  }, 10000)
  ws.once('open', () => {
    ws.close()
    finish([url, idx, 'OPENED'])
  })
  ws.once('unexpected-response', (_req, res) => {
    console.log(res.statusCode, idx, url)
    if (![400, 401, 403, 404, 405, 429].includes(res.statusCode)) {
      finish([url, idx, `HTTP ${res.statusCode}`])
      return
    }
    finish()
  })
  ws.once('error', err => {
    console.log('error', idx, url, err.message)
    finish([url, idx, 'ERROR', err.message])
  })
})))).then(() => {
  console.log('FAILURES', JSON.stringify(failures))
  process.exit(failures.length ? 1 : 0)
})

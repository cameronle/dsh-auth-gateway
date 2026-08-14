const WebSocket = require('/home/hermes/.hermes/node/lib/node_modules/@deepseek-ai/dsh/node_modules/ws')
const targets = [
  'wss://dsh.example.com/api/events.mux',
  'wss://dsh.example.com/api/events.host',
  'wss://dsh.example.com//api/events.mux',
  'wss://dsh.example.com/%2e/api/events.mux',
  'wss://dsh.example.com/api%2fevents.mux',
  'wss://dsh.example.com/API/events.mux',
]
const headersList = [
  {},
  { Authorization: 'Bearer wrong' },
  { Cookie: 'dsh_gateway_session=wrong' },
  { 'X-Forwarded-For': '127.0.0.1', 'CF-Connecting-IP': '127.0.0.1' },
  { Host: '127.0.0.1:3080' },
]
let failures = []
Promise.all(targets.flatMap(url => headersList.map((headers, idx) => new Promise(resolve => {
  const ws = new WebSocket(url, { headers: { Origin: 'https://dsh.example.com', ...headers } })
  const timer = setTimeout(() => { failures.push([url, idx, 'timeout']); try { ws.terminate() } catch {} ; resolve() }, 10000)
  ws.once('open', () => { clearTimeout(timer); failures.push([url, idx, 'OPENED']); ws.close(); resolve() })
  ws.once('unexpected-response', (_req, res) => { clearTimeout(timer); console.log(res.statusCode, idx, url); if (![400,401,403,404,405,429].includes(res.statusCode)) failures.push([url,idx,'HTTP '+res.statusCode]); resolve() })
  ws.once('error', err => { clearTimeout(timer); console.log('error',idx,url,err.message); resolve() })
})))).then(() => { console.log('FAILURES', JSON.stringify(failures)); process.exit(failures.length ? 1 : 0) })

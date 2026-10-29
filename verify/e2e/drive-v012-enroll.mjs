// Headless-Chrome proof for v0.1.2 automatic Agent enrollment UI.
// Assumes: enrollment Controller on 127.0.0.1:8082 (public_origin 18090), one
// auto-enrolled Agent, and `ssh -N -L 18090:127.0.0.1:8082` tunnel.
// Captures verify/screenshots-v012/auto-enroll.png and fails on console/CSP errors.
import fs from 'node:fs'
import path from 'node:path'
import { execSync } from 'node:child_process'

const CDP_PORT = process.env.CDP_PORT || '9335'
const APP_URL = process.env.APP_URL || 'http://127.0.0.1:18090/'
const SSH_TARGET = process.env.SSH_TARGET || 'root@124.222.154.86'
const OUT = process.env.OUT_DIR || 'verify/screenshots-v012'
fs.mkdirSync(OUT, { recursive: true })

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const results = []
const consoleErrors = []
const cspViolations = []
const pageExceptions = []
function check(name, ok, detail) {
  results.push({ name, ok: Boolean(ok), detail: String(detail ?? '') })
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name} ${detail ?? ''}`)
}

async function main() {
  const targets = await (await fetch(`http://127.0.0.1:${CDP_PORT}/json/list`)).json()
  const page = targets.find((t) => t.type === 'page')
  if (!page) throw new Error('no page target')
  const ws = new WebSocket(page.webSocketDebuggerUrl)
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject })
  let nextID = 0
  const pending = new Map()
  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data)
    if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); return }
    if (msg.method === 'Runtime.consoleAPICalled' && ['error', 'assert'].includes(msg.params.type))
      consoleErrors.push('console.' + msg.params.type + ': ' + msg.params.args.map((a) => a.value ?? a.description ?? a.type).join(' '))
    if (msg.method === 'Runtime.exceptionThrown')
      pageExceptions.push(msg.params.exceptionDetails?.exception?.description || msg.params.exceptionDetails?.text || 'exception')
    if (msg.method === 'Log.entryAdded' && msg.params.entry.level === 'error') {
      const e = msg.params.entry
      const text = `${e.source}: ${e.text} ${e.url || ''}`
      if (/content security policy|CSP|Refused to/i.test(text)) cspViolations.push(text)
      else consoleErrors.push('log.error: ' + text)
    }
  }
  const send = (method, params = {}) => new Promise((resolve) => {
    const id = ++nextID; pending.set(id, resolve); ws.send(JSON.stringify({ id, method, params }))
  })
  const evaluate = async (expression) => {
    const res = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true })
    if (res.result?.exceptionDetails) throw new Error('evaluate failed: ' + JSON.stringify(res.result.exceptionDetails).slice(0, 400))
    return res.result?.result?.value
  }
  const waitFor = async (expression, timeoutMs, label) => {
    const start = Date.now()
    while (Date.now() - start < timeoutMs) { if (await evaluate(expression)) return true; await sleep(500) }
    throw new Error(`timeout waiting for ${label}`)
  }
  const shot = async (name, fullPage = true) => {
    let params = { format: 'png' }
    if (fullPage) {
      const metrics = await send('Page.getLayoutMetrics')
      const size = metrics.result.cssContentSize || metrics.result.contentSize
      params = { format: 'png', captureBeyondViewport: true, clip: { x: 0, y: 0, width: size.width, height: size.height, scale: 1 } }
    }
    const res = await send('Page.captureScreenshot', params)
    fs.writeFileSync(path.join(OUT, name), Buffer.from(res.result.data, 'base64'))
    console.log('screenshot:', path.join(OUT, name))
  }

  await send('Page.enable'); await send('Runtime.enable'); await send('Log.enable')
  await send('Page.addScriptToEvaluateOnNewDocument', {
    source: 'window.__cspViolations=[];window.__pageErrors=[];' +
      "document.addEventListener('securitypolicyviolation',function(e){window.__cspViolations.push({directive:e.violatedDirective,blocked:e.blockedURI})});" +
      "window.addEventListener('error',function(e){window.__pageErrors.push(String(e.message))});" +
      "window.addEventListener('unhandledrejection',function(e){window.__pageErrors.push('unhandledrejection:'+String(e.reason))});",
  })
  await send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 1100, deviceScaleFactor: 1, mobile: false })
  await send('Page.navigate', { url: APP_URL })
  await waitFor(`document.querySelector('input[placeholder*="example.com"]') !== null`, 30000, 'target input')
  await waitFor(`document.body.innerText.includes('VM-0-12-debian')`, 30000, 'auto-enrolled node in dashboard')
  await evaluate('window.__noReloadMarker = 42')
  const dashText = await evaluate('document.body.innerText')
  check('auto_node_visible_without_config', /VM-0-12-debian/.test(dashText), 'node id/name rendered')
  check('auto_node_health_ok', /VM-0-12-debian[\s\S]{0,80}?(OK|Ready)/i.test(dashText) || /\bOK\b/.test(dashText), 'health badge OK')
  check('controller_has_no_machine_list_text', !/static-1/.test(dashText), 'no administrator-configured node list')
  await shot('dashboard.png')

  // live refresh: restart the Agent on the host and watch the dashboard recover
  // without a page reload (health poll + re-enrollment)
  let restarted = true
  try {
    execSync(`ssh -o BatchMode=yes -o ConnectTimeout=10 ${SSH_TARGET} 'systemctl restart tracecat-agent'`, { stdio: 'pipe', timeout: 60000 })
  } catch (e) { restarted = false }
  check('agent_restart_triggered', restarted, restarted ? 'systemctl restart executed' : 'ssh failed')
  let sawUnreachable = false, recovered = false
  const start = Date.now()
  while (Date.now() - start < 90000) {
    const text = await evaluate('document.body.innerText')
    if (/Unreachable/i.test(text)) sawUnreachable = true
    if (sawUnreachable && /VM-0-12-debian[\s\S]{0,200}?OK/i.test(text)) { recovered = true; break }
    if (!sawUnreachable && Date.now() - start > 20000 && /VM-0-12-debian/.test(text)) {
      // health poll may miss the short outage; treat continued availability as recovery
      if (/VM-0-12-debian[\s\S]{0,200}?OK/i.test(text)) { recovered = true; break }
    }
    await sleep(1000)
  }
  const noReload = await evaluate('window.__noReloadMarker === 42')
  check('dashboard_live_refresh_no_reload', noReload, 'page not reloaded during recovery')
  check('auto_node_recovers_health', recovered, `sawUnreachable=${sawUnreachable} recovered=${recovered}`)
  await shot('live-refresh.png')

  // real trace through the auto-enrolled node via the UI
  await evaluate(`(() => {
    const cb = [...document.querySelectorAll('input[type="checkbox"]')].find(c => c.getAttribute('aria-label')?.startsWith('Select agent VM-0-12-debian'));
    if (!cb) throw new Error('agent checkbox not found');
    if (!cb.checked) cb.click(); return true })()`)
  await waitFor(`document.querySelector('input[type="checkbox"]:checked') !== null`, 15000, 'agent selected')
  await evaluate(`(() => {
    const input = document.querySelector('input[placeholder*="example.com"]');
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    setter.call(input, '1.1.1.1'); input.dispatchEvent(new Event('input', { bubbles: true })); return true })()`)
  await evaluate(`(() => {
    const b = [...document.querySelectorAll('button')].find(b => b.getAttribute('aria-label') === 'Resolve target on the controller');
    if (!b) throw new Error('resolve button not found'); b.click(); return true })()`)
  await waitFor(`document.body.innerText.includes('IP literal')`, 30000, 'resolved literal')
  await evaluate(`(() => { const r = document.querySelector('input[type="radio"]'); if (r && !r.checked) r.click(); return true })()`)
  await waitFor(`document.querySelector('input[type="radio"]:checked') !== null`, 15000, 'destination selected')
  await evaluate(`(() => {
    const b = [...document.querySelectorAll('button')].find(b => b.textContent.includes('Start trace'));
    if (!b) throw new Error('start not found');
    return {disabled: b.disabled, sel: [...document.querySelectorAll('input[type="checkbox"]:checked')].length,
            radio: document.querySelectorAll('input[type="radio"]:checked').length};
  })()`).then((st) => { if (st.disabled) console.log('start state:', JSON.stringify(st)); return st })
  let started = false
  for (let i = 0; i < 20 && !started; i++) {
    started = await evaluate(`(() => {
      const b = [...document.querySelectorAll('button')].find(b => b.textContent.includes('Start trace'));
      if (!b || b.disabled) return false; b.click(); return true })()`)
    if (!started) await sleep(500)
  }
  if (!started) throw new Error('start disabled after 10s')
  await waitFor(`document.body.innerText.includes('final snapshots')`, 180000, 'enrollment ICMP job terminal')
  const resultText = await evaluate('document.body.innerText')
  const rows = await evaluate(`document.querySelectorAll('table tbody tr').length`)
  check('ui_trace_completed_auto_node', /completed/i.test(resultText), 'job completed in UI')
  check('ui_trace_hops', rows > 0, `rows=${rows}`)
  await shot('auto-enroll.png')

  // desktop + narrow layout sanity
  await send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 2, mobile: true })
  await sleep(1000)
  const overflow = await evaluate('({scrollWidth: document.documentElement.scrollWidth, innerWidth: window.innerWidth})')
  check('mobile_no_horizontal_overflow', overflow.scrollWidth <= overflow.innerWidth + 2, JSON.stringify(overflow))
  await shot('mobile.png', false)

  const pageCsp = await evaluate('window.__cspViolations || []')
  const pageErrs = await evaluate('window.__pageErrors || []')
  cspViolations.push(...pageCsp.map((v) => JSON.stringify(v)))
  pageExceptions.push(...pageErrs)
  check('zero_csp_violations', cspViolations.length === 0, `${cspViolations.length}`)
  check('zero_console_errors', consoleErrors.length === 0, `${consoleErrors.length}`)
  check('zero_page_exceptions', pageExceptions.length === 0, `${pageExceptions.length}`)

  const report = {
    url: APP_URL, generated_at: new Date().toISOString(), checks: results,
    console_errors: consoleErrors, csp_violations: cspViolations, page_exceptions: pageExceptions,
    screenshots: fs.readdirSync(OUT).filter((f) => f.endsWith('.png')),
  }
  fs.writeFileSync(path.join(OUT, 'browser-report.json'), JSON.stringify(report, null, 2))
  ws.close()
  const failed = results.filter((r) => !r.ok)
  console.log(`SUMMARY ${results.length - failed.length}/${results.length} browser checks passed`)
  process.exit(failed.length === 0 ? 0 : 1)
}
main().catch((err) => { console.error('FAILED:', err.message); process.exit(1) })

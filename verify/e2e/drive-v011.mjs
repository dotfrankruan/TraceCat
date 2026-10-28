// Headless-Chrome proof for the v0.1.1 feature set (protocol/port + per-node
// interface selection), over the same SSH-tunnel origin as docs/VERIFICATION.md.
//
// Requires Chrome with --remote-debugging-port and an ssh -L 18090:127.0.0.1:8080
// tunnel. Captures desktop + 390px screenshots to OUT_DIR and fails on any
// console error, uncaught exception or CSP violation.
import fs from 'node:fs'
import path from 'node:path'

const CDP_PORT = process.env.CDP_PORT || '9333'
const APP_URL = process.env.APP_URL || 'http://127.0.0.1:18090/'
const OUT = process.env.OUT_DIR || 'verify/screenshots-v011'
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
  await new Promise((resolve, reject) => {
    ws.onopen = resolve
    ws.onerror = reject
  })
  let nextID = 0
  const pending = new Map()
  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data)
    if (msg.id && pending.has(msg.id)) {
      pending.get(msg.id)(msg)
      pending.delete(msg.id)
      return
    }
    if (msg.method === 'Runtime.consoleAPICalled' && ['error', 'assert'].includes(msg.params.type)) {
      consoleErrors.push('console.' + msg.params.type + ': ' + msg.params.args.map((a) => a.value ?? a.description ?? a.type).join(' '))
    }
    if (msg.method === 'Runtime.exceptionThrown') {
      pageExceptions.push(msg.params.exceptionDetails?.exception?.description || msg.params.exceptionDetails?.text || 'exception')
    }
    if (msg.method === 'Log.entryAdded' && msg.params.entry.level === 'error') {
      const e = msg.params.entry
      const text = `${e.source}: ${e.text} ${e.url || ''}`
      if (/content security policy|CSP|Refused to/i.test(text)) cspViolations.push(text)
      else consoleErrors.push('log.error: ' + text)
    }
  }
  const send = (method, params = {}) =>
    new Promise((resolve) => {
      const id = ++nextID
      pending.set(id, resolve)
      ws.send(JSON.stringify({ id, method, params }))
    })
  const evaluate = async (expression) => {
    const res = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true })
    if (res.result?.exceptionDetails) throw new Error('evaluate failed: ' + JSON.stringify(res.result.exceptionDetails).slice(0, 400))
    return res.result?.result?.value
  }
  const waitFor = async (expression, timeoutMs, label) => {
    const start = Date.now()
    while (Date.now() - start < timeoutMs) {
      if (await evaluate(expression)) return true
      await sleep(400)
    }
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

  await send('Page.enable')
  await send('Runtime.enable')
  await send('Log.enable')
  await send('Page.addScriptToEvaluateOnNewDocument', {
    source:
      'window.__cspViolations=[];window.__pageErrors=[];' +
      "document.addEventListener('securitypolicyviolation',function(e){window.__cspViolations.push({directive:e.violatedDirective,blocked:e.blockedURI})});" +
      "window.addEventListener('error',function(e){window.__pageErrors.push(String(e.message))});" +
      "window.addEventListener('unhandledrejection',function(e){window.__pageErrors.push('unhandledrejection:'+String(e.reason))});",
  })
  await send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 1100, deviceScaleFactor: 1, mobile: false })
  await send('Page.navigate', { url: APP_URL })
  await waitFor(`document.querySelector('input[placeholder*="example.com"]') !== null`, 30000, 'target input')
  await waitFor(
    `document.body.innerText.includes('Debian test host A') && document.body.innerText.includes('Debian test host B')`,
    30000,
    'both agents listed'
  )
  check('two_agents_listed', true, 'both tailnet agents visible')

  // resolve 1.1.1.1 (stable literal; avoids DNS variance)
  await evaluate(`(() => {
    const input = document.querySelector('input[placeholder*="example.com"]');
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    setter.call(input, '1.1.1.1');
    input.dispatchEvent(new Event('input', { bubbles: true }));
    return true;
  })()`)
  await sleep(200)
  await evaluate(`(() => {
    const b = [...document.querySelectorAll('button')].find((b) => b.getAttribute('aria-label') === 'Resolve target on the controller');
    if (!b) throw new Error('resolve button not found');
    b.click(); return true;
  })()`)
  await waitFor(`document.body.innerText.includes('IP literal')`, 30000, 'resolved literal')
  await evaluate(`(() => { const r = document.querySelector('input[type="radio"]'); if (r && !r.checked) r.click(); return true })()`)
  await waitFor(`document.body.innerText.includes('Every selected agent probes this exact numeric IP')`, 15000, 'destination')

  // select both agents -> per-node interface selectors appear
  await evaluate(`(() => {
    const b = [...document.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Select all');
    if (!b) throw new Error('select all not found');
    b.click(); return true;
  })()`)
  await sleep(400)
  const ifaceSelectors = await evaluate(
    `[...document.querySelectorAll('select[aria-label^="Source network interface for"]')].map(s => ({label: s.getAttribute('aria-label'), options: [...s.options].map(o => o.value)}))`
  )
  check('per_node_interface_selectors', ifaceSelectors.length === 2, `selectors=${JSON.stringify(ifaceSelectors)}`)
  check(
    'interface_options_include_eth0',
    ifaceSelectors.every((s) => s.options.includes('eth0')),
    JSON.stringify(ifaceSelectors.map((s) => s.options))
  )
  // pin eth0 for agent A, leave agent B on Automatic
  await evaluate(`(() => {
    const select = [...document.querySelectorAll('select[aria-label^="Source network interface for"]')]
      .find(s => s.getAttribute('aria-label').includes('Debian test host A'));
    if (!select) throw new Error('interface select for agent A not found');
    select.value = 'eth0';
    select.dispatchEvent(new Event('change', { bubbles: true }));
    return true;
  })()`)
  await sleep(300)
  const ifaceChip = await evaluate(`document.body.innerText.includes('iface eth0')`)
  check('interface_override_chip', ifaceChip, 'selected agent shows iface eth0')

  // protocol selector: TCP + port 443
  const protocolGroup = `[...document.querySelectorAll('[role="group"][aria-label="Probe protocol"] button')]`
  const tcpButton = await evaluate(`${protocolGroup}.map(b => b.textContent.trim())`)
  check('protocol_selector_three_options', tcpButton.length === 3 && tcpButton.includes('TCP') && tcpButton.includes('UDP'), JSON.stringify(tcpButton))
  await evaluate(`(() => {
    const b = ${protocolGroup}.find(b => b.textContent.trim() === 'TCP');
    if (!b) throw new Error('TCP button not found');
    b.click(); return true;
  })()`)
  await sleep(300)
  const portValue = await evaluate(`(() => {
    const input = document.querySelector('input[placeholder="80"]');
    if (!input) throw new Error('port input not found');
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    setter.call(input, '443');
    input.dispatchEvent(new Event('input', { bubbles: true }));
    return input.value;
  })()`)
  check('port_input_accepts_443', portValue === '443', `port=${portValue}`)
  await shot('selection.png')

  // run TCP/443 with the interface override
  await evaluate(`(() => {
    const b = [...document.querySelectorAll('button')].find((b) => b.textContent.includes('Start trace'));
    if (!b) throw new Error('start not found');
    if (b.disabled) throw new Error('start disabled');
    b.click(); return true;
  })()`)
  await waitFor(`document.body.innerText.includes('final snapshots')`, 180000, 'tcp terminal job')
  const tcpText = await evaluate('document.body.innerText')
  const tcpRows = await evaluate(`document.querySelectorAll('table tbody tr').length`)
  check('tcp_hop_table', tcpRows > 0, `rows=${tcpRows}`)
  check('tcp_probe_label', /tcp\/443/i.test(tcpText), 'tcp/443 chip visible')
  check('tcp_iface_result', /iface eth0/i.test(tcpText), 'iface eth0 result chip')
  check('tcp_both_nodes', tcpText.includes('Debian test host A') && tcpText.includes('Debian test host B'), 'both node cards')
  check('tcp_completed', /completed/i.test(tcpText), 'completed status present')
  await shot('tcp-results.png')

  // UDP run (default port 33494) without interface override (Automatic)
  await evaluate(`(() => {
    const select = [...document.querySelectorAll('select[aria-label^="Source network interface for"]')]
      .find(s => s.getAttribute('aria-label').includes('Debian test host A'));
    if (select) { select.value = ''; select.dispatchEvent(new Event('change', { bubbles: true })); }
    return true;
  })()`)
  await evaluate(`(() => {
    const b = ${protocolGroup}.find(b => b.textContent.trim() === 'UDP');
    if (!b) throw new Error('UDP button not found');
    b.click(); return true;
  })()`)
  await sleep(300)
  const udpPort = await evaluate(`(() => {
    const input = document.querySelector('input[placeholder="33494"]');
    return input ? input.value : '';
  })()`)
  check('udp_default_port_33494', udpPort === '33494', `port=${udpPort}`)
  await evaluate(`(() => {
    const b = [...document.querySelectorAll('button')].find((b) => b.textContent.includes('Start trace'));
    if (!b || b.disabled) throw new Error('start disabled');
    b.click(); return true;
  })()`)
  await waitFor(`document.body.innerText.includes('final snapshots')`, 180000, 'udp terminal job')
  const udpText = await evaluate('document.body.innerText')
  check('udp_probe_label', /udp\/33494/i.test(udpText), 'udp/33494 chip visible')
  check('udp_hop_table', /udp\/33494/i.test(udpText), 'udp result rendered')
  await shot('udp-results.png')

  // mobile viewport
  await send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 2, mobile: true })
  await sleep(1200)
  const overflow = await evaluate(`({scrollWidth: document.documentElement.scrollWidth, innerWidth: window.innerWidth})`)
  check('mobile_no_horizontal_overflow', overflow.scrollWidth <= overflow.innerWidth + 2, JSON.stringify(overflow))
  await shot('mobile.png', false)

  // browser-level security assertions
  const pageCsp = await evaluate('window.__cspViolations || []')
  const pageErrs = await evaluate('window.__pageErrors || []')
  cspViolations.push(...pageCsp.map((v) => JSON.stringify(v)))
  pageExceptions.push(...pageErrs)
  check('zero_csp_violations', cspViolations.length === 0, `${cspViolations.length}`)
  check('zero_console_errors', consoleErrors.length === 0, `${consoleErrors.length}`)
  check('zero_page_exceptions', pageExceptions.length === 0, `${pageExceptions.length}`)

  const report = {
    url: APP_URL,
    generated_at: new Date().toISOString(),
    checks: results,
    console_errors: consoleErrors,
    csp_violations: cspViolations,
    page_exceptions: pageExceptions,
    screenshots: fs.readdirSync(OUT).filter((f) => f.endsWith('.png')),
  }
  fs.writeFileSync(path.join(OUT, 'browser-report.json'), JSON.stringify(report, null, 2))
  ws.close()
  const failed = results.filter((r) => !r.ok)
  console.log(`SUMMARY ${results.length - failed.length}/${results.length} browser checks passed`)
  process.exit(failed.length === 0 ? 0 : 1)
}

main().catch((err) => {
  console.error('FAILED:', err.message)
  process.exit(1)
})

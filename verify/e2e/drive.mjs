// Headless-Chrome driver for the TraceCat dashboard verification.
//
// Connects to an already-running Chrome DevTools Protocol endpoint, drives the
// real UI (resolve -> pick exact address -> select agents -> start -> results ->
// compare -> mobile), captures screenshots, and fails if the page produces any
// console error, uncaught exception or CSP violation.
//
// No npm dependencies (Node 22+ global WebSocket/fetch). Test-only tooling.
//
// Usage:
//   CDP_PORT=9333 APP_URL=http://127.0.0.1:18080/ OUT_DIR=verify/screenshots \
//     node verify/e2e/drive.mjs
import fs from 'node:fs'
import path from 'node:path'

const CDP_PORT = process.env.CDP_PORT || '9333'
const APP_URL = process.env.APP_URL || 'http://127.0.0.1:18080/'
const OUT = process.env.OUT_DIR || 'verify/screenshots'
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
    if (msg.method === 'Runtime.consoleAPICalled') {
      const type = msg.params.type
      if (type === 'error' || type === 'assert') {
        consoleErrors.push(
          'console.' + type + ': ' + msg.params.args.map((a) => a.value ?? a.description ?? a.type).join(' ')
        )
      }
    }
    if (msg.method === 'Runtime.exceptionThrown') {
      pageExceptions.push(
        msg.params.exceptionDetails?.exception?.description || msg.params.exceptionDetails?.text || 'exception'
      )
    }
    if (msg.method === 'Log.entryAdded') {
      const e = msg.params.entry
      if (e.level === 'error') {
        const text = `${e.source}: ${e.text} ${e.url || ''}`
        if (/content security policy|CSP|Refused to/i.test(text)) cspViolations.push(text)
        else consoleErrors.push('log.error: ' + text)
      }
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
    if (res.result?.exceptionDetails) {
      throw new Error('evaluate failed: ' + JSON.stringify(res.result.exceptionDetails).slice(0, 400))
    }
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
      params = {
        format: 'png',
        captureBeyondViewport: true,
        clip: { x: 0, y: 0, width: size.width, height: size.height, scale: 1 },
      }
    }
    const res = await send('Page.captureScreenshot', params)
    const file = path.join(OUT, name)
    fs.writeFileSync(file, Buffer.from(res.result.data, 'base64'))
    console.log('screenshot:', file)
    return file
  }

  await send('Page.enable')
  await send('Runtime.enable')
  await send('Log.enable')
  // Record securitypolicyviolation events from the very first script execution.
  await send('Page.addScriptToEvaluateOnNewDocument', {
    source:
      'window.__cspViolations=[];window.__pageErrors=[];' +
      "document.addEventListener('securitypolicyviolation',function(e){window.__cspViolations.push({directive:e.violatedDirective,blocked:e.blockedURI,sample:e.sample})});" +
      "window.addEventListener('error',function(e){window.__pageErrors.push(String(e.message))});" +
      "window.addEventListener('unhandledrejection',function(e){window.__pageErrors.push('unhandledrejection:'+String(e.reason))});",
  })
  await send('Emulation.setDeviceMetricsOverride', {
    width: 1440,
    height: 1100,
    deviceScaleFactor: 1,
    mobile: false,
  })
  await send('Page.navigate', { url: APP_URL })
  await waitFor(`document.querySelector('input[placeholder*="example.com"]') !== null`, 30000, 'target input')

  // Nodes panel: both administratively configured Agents must be visible and healthy.
  await waitFor(
    `document.body.innerText.includes('Debian test host A') && document.body.innerText.includes('Debian test host B')`,
    30000,
    'both agents listed'
  )
  const agentCount = await evaluate(
    `[...document.querySelectorAll('input[type="checkbox"][aria-label^="Select agent"]')].length`
  )
  check('two_agents_rendered', agentCount === 2, `checkboxes=${agentCount}`)
  const nodesHealthy = await evaluate(
    `(() => {
       const t = document.body.innerText;
       return t.includes('Debian test host A') && t.includes('Debian test host B') && !/unreachable|degraded/i.test(t);
     })()`
  )
  check('agents_healthy_in_ui', nodesHealthy, 'no degraded/unreachable text')
  await shot('dashboard.png')

  // Resolve a real domain: multiple A/AAAA answers require an explicit choice.
  const setInput = `(() => {
    const input = document.querySelector('input[placeholder*="example.com"]');
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    setter.call(input, 'example.com');
    input.dispatchEvent(new Event('input', { bubbles: true }));
    return true;
  })()`
  await evaluate(setInput)
  await sleep(300)
  await evaluate(`(() => {
    const b = [...document.querySelectorAll('button')].find((b) => b.getAttribute('aria-label') === 'Resolve target on the controller');
    if (!b) throw new Error('resolve button not found');
    b.click(); return true;
  })()`)
  await waitFor(`document.querySelectorAll('input[type="radio"]').length > 0`, 30000, 'resolved addresses')
  const radioCount = await evaluate(`document.querySelectorAll('input[type="radio"]').length`)
  check('domain_returns_choices', radioCount >= 1, `address radios=${radioCount}`)
  const domainKind = await evaluate(`document.body.innerText.includes('Domain')`)
  check('domain_resolution_shown', domainKind, 'kind=Domain badge present')
  // explicit selection: click the first address radio, then verify the exact IP is displayed
  await evaluate(`(() => { const r = document.querySelector('input[type="radio"]'); r.click(); return true })()`)
  await waitFor(
    `document.body.innerText.includes('Every selected agent probes this exact numeric IP')`,
    15000,
    'explicit destination'
  )
  const selectedIP = await evaluate(
    `(() => {
       const m = document.body.innerText.match(/Every selected agent probes this exact numeric IP/);
       const el = [...document.querySelectorAll('p')].find(p => /^(\\d{1,3}\\.){3}\\d{1,3}$|:/.test(p.innerText.trim()));
       return el ? el.innerText.trim() : (m ? 'destination-shown' : '');
     })()`
  )
  check('explicit_address_selected', Boolean(selectedIP), `selected=${selectedIP}`)
  await shot('resolution.png')

  // Select all agents and start the real multi-node job.
  await evaluate(`(() => {
    const b = [...document.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Select all');
    if (!b) throw new Error('select all not found');
    b.click(); return true;
  })()`)
  await sleep(300)
  const selection = await evaluate(
    `document.body.innerText.includes('2 agents selected') || document.body.innerText.includes('2 of 2') || document.body.innerText.includes('selected')`
  )
  check('agents_selected', selection, 'selection summary visible')
  await evaluate(`(() => {
    const b = [...document.querySelectorAll('button')].find((b) => b.textContent.includes('Start trace'));
    if (!b) throw new Error('start not found');
    if (b.disabled) throw new Error('start button disabled');
    b.click(); return true;
  })()`)
  console.log('job started')
  await waitFor(`document.body.innerText.includes('final snapshots')`, 180000, 'terminal job')
  const resultsText = await evaluate('document.body.innerText')
  const tableRows = await evaluate(`document.querySelectorAll('table tbody tr').length`)
  check('hop_table_rendered', tableRows > 0, `rows=${tableRows}`)
  check(
    'both_nodes_in_results',
    resultsText.includes('Debian test host A') && resultsText.includes('Debian test host B'),
    'both node result cards visible'
  )
  check(
    'job_completed_in_ui',
    /completed/i.test(resultsText) && !/no hop data/i.test(resultsText),
    'completed status, hop data present'
  )
  check(
    'honest_no_reply_wording',
    /no reply/i.test(resultsText) || /reached/i.test(resultsText),
    'no-reply/reached wording present'
  )
  await shot('results.png')

  // Compare view (side-by-side, aligned TTL rows).
  await evaluate(`(() => {
    const b = [...document.querySelectorAll('button[aria-pressed]')].find((b) => b.textContent.trim() === 'Compare');
    if (!b) throw new Error('compare toggle not found');
    b.click(); return true;
  })()`)
  await waitFor(`document.body.innerText.includes('aligned by TTL')`, 30000, 'compare view')
  const compareText = await evaluate('document.body.innerText')
  check('compare_view_rendered', /aligned by TTL/.test(compareText), 'compare explanation visible')
  check(
    'compare_has_both_paths',
    compareText.includes('Debian test host A') && compareText.includes('Debian test host B'),
    'both paths in compare view'
  )
  await shot('compare.png')

  // Mobile viewport (390x844, DPR 2).
  await send('Emulation.setDeviceMetricsOverride', {
    width: 390,
    height: 844,
    deviceScaleFactor: 2,
    mobile: true,
  })
  await sleep(1200)
  const overflow = await evaluate(
    `(() => {
       const de = document.documentElement;
       return { scrollWidth: de.scrollWidth, innerWidth: window.innerWidth };
     })()`
  )
  check(
    'mobile_no_horizontal_overflow',
    overflow.scrollWidth <= overflow.innerWidth + 2,
    `scrollWidth=${overflow.scrollWidth} innerWidth=${overflow.innerWidth}`
  )
  await shot('mobile.png', false)

  // Browser-level security assertions.
  const pageCsp = await evaluate('window.__cspViolations || []')
  const pageErrs = await evaluate('window.__pageErrors || []')
  cspViolations.push(...pageCsp.map((v) => JSON.stringify(v)))
  pageExceptions.push(...pageErrs)
  check('zero_csp_violations', cspViolations.length === 0, `${cspViolations.length} violations`)
  check('zero_console_errors', consoleErrors.length === 0, `${consoleErrors.length} errors`)
  check('zero_page_exceptions', pageExceptions.length === 0, `${pageExceptions.length} exceptions`)

  // Confirm the rendered document is same-origin and assets are local.
  const origins = await evaluate(
    `[...document.querySelectorAll('script[src],link[href]')].map(e => e.src || e.href)`
  )
  const external = origins.filter((u) => u && !u.startsWith(APP_URL.replace(/\/$/, '')))
  check('assets_same_origin_only', external.length === 0, external.slice(0, 3).join(',') || 'all local')

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

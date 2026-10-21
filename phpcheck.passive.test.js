const assert = require('node:assert/strict')
const { spawn } = require('node:child_process')
const { once } = require('node:events')
const { mkdtemp, rm, writeFile } = require('node:fs/promises')
const http = require('node:http')
const { tmpdir } = require('node:os')
const path = require('node:path')
const { test } = require('node:test')
const { fingerprint, MAX_BODY_BYTES } = require('./skills/phpcheck-url/scripts/fingerprint')

async function runCapture(t, capture, mode = '--response', extra = []) {
  const dir = await mkdtemp(path.join(tmpdir(), 'phpcheck-passive-'))
  t.after(() => rm(dir, { recursive: true, force: true }))
  const file = path.join(dir, 'capture.json')
  await writeFile(file, JSON.stringify(capture))
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(__dirname, 'phpcheck.js'), mode, file, '--json', ...extra])
    let stdout = '', stderr = ''
    child.stdout.on('data', data => { stdout += data })
    child.stderr.on('data', data => { stderr += data })
    child.on('error', reject)
    child.on('close', code => resolve({ code, stdout, stderr, report: stdout ? JSON.parse(stdout) : null }))
  })
}

function response(overrides = {}) {
  return { url: 'https://appliance.example/login', headers: { Server: 'nginx' }, mimeType: 'text/html', body: '', ...overrides }
}

for (const [name, overrides, presence, evidenceType] of [
  ['extensionless PHP with stripped banner', { headers: { 'Set-Cookie': 'PHPSESSID=SECRET; Secure' } }, 'likely', 'php_cookie'],
  ['framework cookie', { headers: { 'Set-Cookie': 'laravel_session=SECRET; HttpOnly' } }, 'likely', 'php_cookie'],
  ['renamed cookie with PHP form', { headers: { 'Set-Cookie': 'vendor_session=SECRET' }, body: '<form action="/auth.php">' }, 'possible', 'php_endpoint'],
  ['renamed cookie without clues', { headers: { 'Set-Cookie': 'vendor_session=SECRET' } }, 'undetermined', null],
  ['PHP error', { body: '<b>Fatal error</b>: Uncaught Error in <b>/srv/auth.php</b> on line <b>12</b>' }, 'advertised_or_observed', 'php_error'],
  ['PHP redirect', { headers: { Location: '/php/login.php' } }, 'possible', 'php_endpoint'],
  ['PHP response URL', { url: 'https://appliance.example/login.php' }, 'possible', 'php_endpoint'],
  ['CMS metadata', { body: '<meta name="generator" content="WordPress 6.0">' }, 'likely', 'php_framework'],
  ['static PHP article', { body: '<h1>PHP/8.4.27 and PAN-OS</h1><p>PHPSESSID is a cookie.</p>' }, 'undetermined', null],
  ['binary content', { mimeType: 'image/png', body: '<form action="/auth.php">' }, 'undetermined', null],
]) {
  test(name, async t => {
    const { code, report, stderr } = await runCapture(t, response(overrides))
    assert.equal(stderr, '')
    assert.equal(code, 3)
    const result = report.results[0]
    assert.equal(result.php_presence, presence)
    assert.equal(result.php_version, null)
    assert.equal(result.patch_status, 'unknown')
    assert.equal(result.fix_verified, false)
    if (evidenceType) assert.ok(result.evidence.some(e => e.type === evidenceType))
    else assert.deepEqual(result.evidence, [])
    assert.ok(!JSON.stringify(report).includes('SECRET'))
  })
}

for (const product of ['PAN-OS', 'Panorama']) {
  test(`${product} needs multiple markers and never implies patch status`, async t => {
    const ui = product === 'Panorama' ? 'panorama_webui' : 'firewall_webui'
    const { report } = await runCapture(t, response({
      body: `<title>${product}</title><script src="/php-packages/${ui}/js/app.js"></script>`,
    }))
    const result = report.results[0]
    assert.deepEqual(result.products, [product])
    assert.equal(result.php_presence, 'inferred_from_product')
    assert.equal(result.php_version, null)
    assert.equal(result.patch_status, 'unknown')
    assert.equal(fingerprint(response({ body: `<title>${product}</title>` })).php_presence, 'undetermined')
  })
}

test('header version is classified independently of body claims and product markers', async t => {
  const { code, report } = await runCapture(t, response({
    headers: { 'X-Powered-By': 'PHP/8.4.26' }, body: 'PHP/8.4.27',
  }))
  assert.equal(code, 1)
  assert.equal(report.results[0].php_version, '8.4.26')
  assert.equal(report.results[0].patch_status, 'vulnerable')
  assert.equal(report.results[0].assessment_basis, 'advertised_version_cutoff')
})

test('conflicting banners preserve all advertised versions and choose the conservative status', async t => {
  const { report } = await runCapture(t, response({
    headers: [{ name: 'Server', value: 'PHP/8.4.27' }, { name: 'X-Powered-By', value: 'PHP/9.0.0' }],
  }))
  assert.equal(report.results[0].patch_status, 'unknown')
  assert.deepEqual(report.results[0].php_versions, ['8.4.27', '9.0.0'])
})

test('HAR analysis makes zero requests, keeps origins separate, and decodes captured base64', async t => {
  let requests = 0
  const server = http.createServer((req, res) => { requests++; res.end() })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.after(() => new Promise(resolve => server.close(resolve)))
  const url = `http://127.0.0.1:${server.address().port}/login?token=SECRET`
  const har = { log: { entries: [
    { request: { url }, startedDateTime: '2026-10-21T10:00:00Z', response: {
      status: 302, headers: [{ name: 'Location', value: 'https://other.example/auth.php?token=SECRET' }],
      content: { mimeType: 'text/html', text: '' },
    } },
    { request: { url: 'https://other.example/login' }, response: {
      status: 200, headers: [{ name: 'X-Powered-By', value: 'PHP/8.4.27' }],
      content: { mimeType: 'text/html', encoding: 'base64', text: Buffer.from('<form action="/login.php">').toString('base64') },
    } },
  ] } }
  const { code, report } = await runCapture(t, har, '--har')
  assert.equal(requests, 0)
  assert.equal(report.network_requests, 0)
  assert.equal(report.mode, 'passive')
  assert.equal(code, 3)
  assert.equal(report.results[0].patch_status, 'unknown')
  assert.equal(report.results[0].captured_at, '2026-10-21T10:00:00.000Z')
  assert.equal(report.results[1].patch_status, 'ok')
  assert.ok(report.results[1].evidence.some(e => e.source === 'body'))
  assert.ok(!JSON.stringify(report).includes('SECRET'))
})

test('unknown dominates OK in a capture; vulnerable dominates unknown', async t => {
  const entry = headers => ({ request: { url: 'https://example.com/' }, response: { headers, content: {} } })
  const entries = [entry([{ name: 'Server', value: 'PHP/8.4.27' }]), entry([])]
  assert.equal((await runCapture(t, { log: { entries } }, '--har')).code, 3)
  entries.push(entry([{ name: 'Server', value: 'PHP/8.4.26' }]))
  assert.equal((await runCapture(t, { log: { entries } }, '--har')).code, 1)
})

test('only a bounded body is inspected', async t => {
  const { report } = await runCapture(t, response({ body: ' '.repeat(MAX_BODY_BYTES) + '<form action="/auth.php">' }))
  assert.equal(report.results[0].body_truncated, true)
  assert.equal(report.results[0].php_presence, 'undetermined')
})

for (const capture of [null, {}, { url: 'file:///etc/passwd' }, response({ headers: [null] }), response({ body: 42 })]) {
  test('malformed capture fails without reporting a safe result', async t => {
    const result = await runCapture(t, capture)
    assert.equal(result.code, 2)
    assert.equal(result.report, null)
    assert.ok(result.stderr)
  })
}

test('capture and network modes cannot be combined', async t => {
  const result = await runCapture(t, response(), '--response', ['https://example.com'])
  assert.equal(result.code, 2)
  assert.match(result.stderr, /exactly one/)
})

test('oversized captures are rejected', async t => {
  const result = await runCapture(t, response({ body: 'x'.repeat(16 * 1024 * 1024) }))
  assert.equal(result.code, 2)
  assert.match(result.stderr, /16 MiB/)
})

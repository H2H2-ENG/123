#!/usr/bin/env node
const { execFileSync } = require('node:child_process')
const { parseArgs } = require('node:util')
const { createReadStream } = require('node:fs')
const { fingerprint, MAX_BODY_BYTES } = require('./fingerprint')

const VERSION = '1.1.0'
// Vulnerable version cutoffs as of 2026-10-20. A newer stable patch in a
// listed branch is OK by this table; unlisted branches remain unknown.
const VULNERABLE_THROUGH = {
  '5.4': 45, '5.5': 38, '5.6': 40,
  '7.0': 33, '7.1': 33, '7.2': 34, '7.3': 33, '7.4': 33,
  '8.0': 30, '8.1': 34, '8.2': 34, '8.3': 35, '8.4': 26, '8.5': 11,
}
const USAGE = 'Usage: node phpcheck.js URL [--timeout SECONDS] [--json]\n' +
  '       node phpcheck.js --har FILE [--json]\n' +
  '       node phpcheck.js --response FILE [--json]\n' +
  '       node phpcheck.js --local [--php PATH] [--json]\n' +
  '       node phpcheck.js --version'

function patchStatus(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)([-+~].*)?$/.exec(version || '')
  if (!match) return 'unknown'
  const cutoff = VULNERABLE_THROUGH[`${Number(match[1])}.${Number(match[2])}`]
  if (cutoff === undefined) return 'unknown'
  if (Number(match[3]) <= cutoff) return 'vulnerable'
  // A development build of the next patch is not evidence of a stable fix.
  if (/(?:^|[-+~.])(?:dev|alpha|beta|rc)/i.test(match[4] || '')) return 'unknown'
  return 'ok'
}

async function urlHeaders(address, timeout) {
  if (/[\x00-\x20\x7f]/.test(address)) throw new Error('URL contains spaces or control characters')
  const url = new URL(address)
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Use an http:// or https:// URL')
  if (url.username || url.password || url.hash) throw new Error('URL credentials and fragments are not supported')
  const headers = []
  for (const method of ['HEAD', 'GET']) {
    const response = await fetch(url, {
      method, redirect: 'manual', signal: AbortSignal.timeout(Math.ceil(timeout * 1000)),
    })
    headers.push(response.headers.get('server') || '', response.headers.get('x-powered-by') || '')
    await response.body?.cancel()
    if (![405, 501].includes(response.status)) break
  }
  return headers.join('\n')
}

async function capturedResponses(file, har) {
  const chunks = []
  let size = 0
  for await (const chunk of createReadStream(file)) {
    size += chunk.length
    if (size > 16 * 1024 * 1024) throw new Error('Capture exceeds 16 MiB limit')
    chunks.push(chunk)
  }
  const data = JSON.parse(Buffer.concat(chunks).toString('utf8'))
  const records = har ? data?.log?.entries : [data]
  if (!Array.isArray(records) || !records.length || records.length > 10000) {
    throw new Error('Capture must contain 1 to 10000 responses')
  }
  return records.map(record => {
    const response = har ? record?.response : record
    const url = har ? record?.request?.url : record?.url
    if (!response || typeof url !== 'string') throw new Error('Each response needs a URL')
    const parsed = new URL(url)
    if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Capture URLs must use HTTP(S)')
    // Preserve attribution without copying query strings, fragments, or credentials.
    parsed.username = parsed.password = parsed.search = parsed.hash = ''
    const headers = response.headers || []
    const validHeaders = Array.isArray(headers)
      ? headers.every(h => h && typeof h.name === 'string' && typeof h.value === 'string')
      : typeof headers === 'object' && Object.values(headers).every(v =>
        typeof v === 'string' || (Array.isArray(v) && v.every(s => typeof s === 'string')))
    if (!validHeaders) throw new Error('Invalid response headers')
    const content = har ? (response.content || {}) : response
    if (typeof content !== 'object' || Array.isArray(content)) throw new Error('Invalid response content')
    if (response.status !== undefined && (!Number.isInteger(response.status) || response.status < 0 || response.status > 599)) {
      throw new Error('Invalid HTTP status')
    }
    const encoded = har ? (content.text ?? '') : (content.body ?? '')
    if (typeof encoded !== 'string' || (content.mimeType !== undefined && typeof content.mimeType !== 'string')) {
      throw new Error('Response body and MIME type must be strings')
    }
    if (har && content.encoding && content.encoding !== 'base64') throw new Error('Unsupported HAR content encoding')
    const bytes = Buffer.from(encoded, har && content.encoding === 'base64' ? 'base64' : 'utf8')
    return {
      url: parsed.href, status: response.status ?? null,
      captured_at: har && typeof record.startedDateTime === 'string' && Number.isFinite(Date.parse(record.startedDateTime))
        ? new Date(record.startedDateTime).toISOString() : null,
      headers, body: bytes.subarray(0, MAX_BODY_BYTES).toString('utf8'),
      mimeType: content.mimeType || '', bodyTruncated: bytes.length > MAX_BODY_BYTES,
    }
  })
}

function classifyVersions(versions) {
  let version = null, status = 'unknown'
  for (const candidate of versions) {
    const candidateStatus = patchStatus(candidate)
    if (version === null || candidateStatus === 'vulnerable' || status === 'ok') {
      version = candidate
      status = candidateStatus
    }
    if (status === 'vulnerable') break
  }
  return { version, status }
}

async function passiveReport(values) {
  const responses = await capturedResponses(values.har || values.response, Boolean(values.har))
  const results = responses.map(response => {
    const finding = fingerprint(response)
    const { version, status } = classifyVersions(finding.php_versions)
    return {
      url: response.url, http_status: response.status, captured_at: response.captured_at,
      ...finding, php_version: version, patch_status: status,
      assessment_basis: version ? 'advertised_version_cutoff' : 'insufficient_version_evidence',
      fix_verified: false,
    }
  })
  const code = results.some(r => r.patch_status === 'vulnerable') ? 1
    : results.every(r => r.patch_status === 'ok') ? 0 : 3
  const report = { mode: 'passive', network_requests: 0, analyzed_at: new Date().toISOString(), results, exit_code: code }
  console.log(values.json ? JSON.stringify(report) : results.map(r =>
    `${r.patch_status.toUpperCase()}: ${r.url} — PHP ${r.php_presence}${r.php_version ? ' (' + r.php_version + ')' : ''}`
  ).join('\n'))
  process.exitCode = code
}

async function main() {
  let values, address, timeout
  try {
    const args = parseArgs({
      allowPositionals: true,
      options: {
        local: { type: 'boolean' },
        har: { type: 'string' },
        response: { type: 'string' },
        php: { type: 'string', default: 'php' },
        timeout: { type: 'string', default: '10' },
        json: { type: 'boolean' },
        version: { type: 'boolean' },
        help: { type: 'boolean', short: 'h' },
      },
    })
    values = args.values
    if (values.version) return console.log(VERSION)
    if (values.help) return console.log(USAGE)
    address = args.positionals[0]
    if (args.positionals.length > 1 || [Boolean(address), Boolean(values.local),
      values.har !== undefined, values.response !== undefined].filter(Boolean).length !== 1) {
      throw new Error('Provide exactly one of URL, --local, --har FILE, or --response FILE')
    }
    if (values.har === '' || values.response === '') throw new Error('Capture file path must not be empty')
    timeout = Number(values.timeout)
    if (!values.local && !(timeout > 0 && timeout <= 60)) throw new Error('--timeout must be greater than 0 and at most 60 seconds')
  } catch (error) {
    console.error(error.message + '\n' + USAGE)
    process.exitCode = 2
    return
  }

  if (values.har || values.response) {
    try { await passiveReport(values) } catch (error) {
      // Do not echo JSON parser errors, which may include captured secrets.
      const reason = error instanceof SyntaxError ? 'Invalid capture JSON or URL' : error.message
      console.error(reason)
      process.exitCode = 2
    }
    return
  }

  let version = null, error = null, status = 'unknown'
  try {
    const text = values.local
      ? execFileSync(values.php, ['-v'], { encoding: 'utf8', timeout: 10000 })
      : await urlHeaders(address, timeout)
    // Local output includes copyright text and may include startup warnings.
    const pattern = values.local ? /^PHP (\d[^\s,;)]*)/gm : /\bPHP[ /]([^\s,;)]+)/gi
    // Do not let an OK banner hide a vulnerable or unrecognized PHP version.
    const classified = classifyVersions([...text.matchAll(pattern)].map(match => match[1]))
    version = classified.version
    status = classified.status
  } catch (exc) {
    error = exc.message
  }

  const code = { ok: 0, vulnerable: 1, unknown: 3 }[status]
  const reason = error || (version ? 'PHP ' + version : 'PHP version not found')
  const report = { patch_status: status, php_version: version, reason, exit_code: code }
  console.log(values.json ? JSON.stringify(report) : status.toUpperCase() + ': ' + reason)
  process.exitCode = code
}

main()

const MAX_BODY_BYTES = 256 * 1024

// Analyze supplied evidence only. This module never makes requests or follows links.
function fingerprint({ url, headers = [], body = '', mimeType = '', bodyTruncated = false }) {
  const evidence = []
  const products = []
  const versions = []
  const add = (type, source, confidence, indicator) => {
    evidence.push({ type, source, confidence, indicator })
  }
  const headerList = Array.isArray(headers)
    ? headers
    : Object.entries(headers).flatMap(([name, values]) =>
      (Array.isArray(values) ? values : [values]).map(value => ({ name, value })))
  for (const { name, value } of headerList) {
    const lower = name.toLowerCase()
    if (['server', 'x-powered-by'].includes(lower) && /\bPHP\b/i.test(value)) {
      add('php_banner', `header:${lower}`, 'high', 'PHP advertised')
      for (const match of value.matchAll(/\bPHP[ /]([^\s,;)]+)/gi)) {
        // Keep untrusted banner tokens bounded; never promote a truncated token.
        if (match[1].length <= 64) versions.push(match[1])
      }
    }
    if (lower === 'set-cookie') {
      // Retain only the recognized cookie name, never session values or tokens.
      const cookie = /^\s*(PHPSESSID|laravel_session|CAKEPHP|ci_session)=/i.exec(value)
      if (cookie) add('php_cookie', 'header:set-cookie', 'medium', cookie[1])
    }
    if (lower === 'location' && phpPath(value, url)) {
      add('php_endpoint', 'header:location', 'low', 'Redirect path has .php extension')
    }
  }
  if (phpPath(url, url)) add('php_endpoint', 'url', 'low', 'Response path has .php extension')

  const bytes = Buffer.from(body)
  const text = bytes.subarray(0, MAX_BODY_BYTES).toString('utf8')
  const contentType = mimeType || headerList.find(h => h.name.toLowerCase() === 'content-type')?.value || ''
  // Avoid interpreting downloaded archives, images, and arbitrary binaries as HTML.
  if (/^(?:text\/(?:html|plain)|application\/xhtml\+xml)(?:;|$)/i.test(contentType)) {
    if (/<b>(?:Fatal error|Warning|Parse error)<\/b>:[\s\S]{0,500}?\bin <b>[^<]+\.php<\/b> on line <b>\d+<\/b>/i.test(text) ||
        /(?:^|\n)(?:PHP )?(?:Fatal error|Parse error|Warning):[^\n]{0,500}\.php(?: on line \d+|:\d+)/i.test(text)) {
      add('php_error', 'body', 'high', 'PHP-format runtime error')
    }
    // Attribute context avoids flagging a prose discussion of PHP or code samples.
    if (/\b(?:href|src|action)\s*=\s*["'][^"'<>]{0,2048}\.php(?:[/?#][^"'<>]*)?["']/i.test(text)) {
      add('php_endpoint', 'body', 'low', 'Linked resource or form action has .php extension')
    }
    if (/<meta\b[^>]*\bname\s*=\s*["']generator["'][^>]*\bcontent\s*=\s*["'](?:WordPress|Drupal|Joomla!?)\b/i.test(text)) {
      add('php_framework', 'body', 'medium', 'PHP CMS generator metadata')
    }
    // Require two independent markers. Do not infer PHP from a prose mention
    // of Palo Alto Networks, GlobalProtect, or Panorama alone.
    if (/<title\b[^>]*>[^<]*(?:Palo Alto Networks|PAN-OS|Panorama)[^<]*<\/title>/i.test(text) &&
        /(?:["'])\/(?:php\/login\.php|php-packages\/(?:firewall_webui|panorama_webui)\/)/i.test(text)) {
      const product = /php-packages\/panorama_webui\//i.test(text) || /<title\b[^>]*>[^<]*Panorama/i.test(text)
        ? 'Panorama' : 'PAN-OS'
      products.push(product)
      add('product_fingerprint', 'body', 'medium', `${product}: title and management UI path`)
    }
  }
  const direct = evidence.filter(e => e.type !== 'product_fingerprint')
  let presence = 'undetermined'
  if (direct.some(e => e.confidence === 'high')) presence = 'advertised_or_observed'
  else if (direct.some(e => e.confidence === 'medium')) presence = 'likely'
  else if (products.length) presence = 'inferred_from_product'
  else if (direct.length) presence = 'possible'
  return {
    php_presence: presence, php_versions: [...new Set(versions)], products, evidence,
    body_truncated: bodyTruncated || bytes.length > MAX_BODY_BYTES,
  }
}

function phpPath(value, base) {
  try { return /\.php(?:\/|$)/i.test(new URL(value, base).pathname) } catch { return false }
}

module.exports = { fingerprint, MAX_BODY_BYTES }

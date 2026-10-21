# PHP Version Checker

Check a website or local PHP version without exploit requests. Uses Node.js. No packages to install.

To install both skills, ask Codex:

```text
$skill-installer install both skills from https://github.com/openai/php2shell-checker
```

Use [phpcheck-server](skills/phpcheck-server/SKILL.md) when you have server
access, or [phpcheck-url](skills/phpcheck-url/SKILL.md) when you only have a URL:

```text
$phpcheck-server check the PHP version serving my site
$phpcheck-url check example.com
```

## Run directly

Check a website:

```sh
node phpcheck.js "https://example.com"
```

Check the local CLI PHP

```sh
node phpcheck.js --local
```

## Strictly passive fingerprinting

Analyze responses already captured during ordinary browsing. These modes read
local files and **make zero network requests**. They do not follow redirects,
visit linked resources, guess endpoints, send payloads, or provoke errors.
The original URL mode still sends HTTP requests and is not strictly passive.

```sh
node phpcheck.js --har browsing.har --json
node phpcheck.js --response response.json --json
```

`--har` accepts a HAR with `log.entries[].request.url` and
`log.entries[].response` (headers and optional content). Text and base64 HAR
content are supported. Entries remain separate, including redirects and
responses from different origins. A redirect header is evidence, not permission
to fetch its destination. HAR files without saved response bodies can still
provide header and cookie evidence.

`--response` accepts one saved response in this JSON format:

```json
{
  "url": "https://appliance.example/login",
  "status": 200,
  "headers": [
    { "name": "Server", "value": "nginx" },
    { "name": "Set-Cookie", "value": "PHPSESSID=example; Secure; HttpOnly" }
  ],
  "mimeType": "text/html",
  "body": "<form action=\"/php/login.php\"></form>"
}
```

Headers may alternatively be an object whose values are strings or arrays of
strings. Header arrays preserve duplicate `Set-Cookie` fields. Body analysis
requires a text/html, text/plain, or application/xhtml+xml MIME type, supplied
in `mimeType` or the response Content-Type header. Inputs are limited to 16 MiB
and 10,000 responses; at most 256 KiB of each body is inspected.

Passive JSON output has `mode: "passive"`, `network_requests: 0`, an analysis
timestamp, per-response `results`, and an aggregate `exit_code`. Each result
separates PHP presence from the advertised-version assessment:

| `php_presence` | Meaning |
| --- | --- |
| `advertised_or_observed` | A PHP banner or recognizable runtime error was observed. |
| `likely` | A recognized PHP/framework cookie or CMS generator marker was observed. |
| `inferred_from_product` | Multiple PAN-OS or Panorama UI markers matched a product known to embed PHP. |
| `possible` | A response URL, redirect, resource link, or form action uses a `.php` path. |
| `undetermined` | No recognized evidence; this does **not** establish PHP absence. |

`evidence` records the indicator type, header/body/URL source, and qualitative
confidence. Confidence is heuristic, not a calibrated probability. Product
matches and PHP-looking paths can be imitated or stale. Only versions advertised
in Server or X-Powered-By feed the existing cutoff comparison; body text,
framework versions, and product identities never establish a PHP version or fix.
Every passive result includes `fix_verified: false` and `assessment_basis`.

The aggregate exit code is 1 if any response advertises a vulnerable version,
otherwise 3 if any response is unknown, otherwise 0. Malformed or oversized
captures exit 2. An OK result for one captured response does not clear other
responses, origins, or unobserved backends.

Reports omit cookie values, raw headers, and response bodies, and remove URL
credentials, query strings, and fragments. URL paths are retained for attribution
and may themselves contain sensitive information. Handle captures and reports
accordingly. Captures may be stale, headers may be forged or rewritten, and
fully concealed PHP may remain undetectable.

## Results

| Result | Exit code | Meaning |
| --- | --- | --- |
| `OK` | `0` | Stable PHP patch version above the embedded cutoff for a listed major/minor branch. |
| `VULNERABLE` | `1` | PHP version at or below the embedded cutoff for that branch. |
| `UNKNOWN` | `3` | No PHP version or response, an unrecognized version/branch, or a newer prerelease build. |

Use `--json` for machine-readable output (`patch_status` is `ok`, `vulnerable`,
or `unknown`). Invalid arguments exit with code `2`.

## Tests

```sh
node --test phpcheck.test.js phpcheck.passive.test.js
```

Tests use local HTTP servers, a fake PHP executable, and saved response/HAR
fixtures. They verify passive mode makes no requests, checks each response
independently, handles hidden PHP indicators, bounds input, and preserves
existing CLI behavior. No PHP installation or external website is required.

## Limitations

Version assessment only evaluates versions exposed in HTTP response headers or by
`php -v`. It reads `X-Powered-By` and `Server`, sends `HEAD`, and falls back to
`GET` only when `HEAD` returns 405 or 501 in URL mode. URL mode does not follow
redirects or inspect response bodies. Passive capture modes additionally inspect
saved bodies and other indicators for PHP presence; without an advertised version,
patch status remains `UNKNOWN`.

`OK` is a version comparison against the embedded October 20, 2026 cutoffs,
assuming subsequent stable patches in each listed branch contain the fix;
it does not independently verify a security fix. Check the cutoffs against
the official PHP security release when its affected and fixed versions are
published. Headers can be hidden or changed, and distribution backports may
not change the upstream version. `UNKNOWN` does not mean the target is patched.

## Contributing

OpenAI is not accepting external code contributions to this project. Bug
reports and non-code feedback are welcome through GitHub issues. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

This project is licensed under the [Apache License 2.0](LICENSE).

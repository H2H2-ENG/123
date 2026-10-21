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

## Results

| Result | Exit code | Meaning |
| --- | --- | --- |
| `OK` | `0` | Stable PHP version at or above the fixed version for its branch: 8.2.35, 8.3.36, 8.4.27 or 8.5.12. |
| `VULNERABLE` | `1` | PHP version below the fixed version for its branch, or any PHP 5.4 to 8.1 version (no upstream fix). |
| `UNKNOWN` | `3` | No PHP version or response, an unrecognized version/branch, or a newer prerelease build. |

Use `--json` for machine-readable output (`patch_status` is `ok`, `vulnerable`,
or `unknown`). Invalid arguments exit with code `2`.

## Tests

```sh
node --test phpcheck.test.js
```

Tests run the CLI against local HTTP servers simulating PHP response headers;
no PHP installation or external website is required.

## Limitations

The checker only evaluates versions exposed in HTTP response headers or by
`php -v`. It reads `X-Powered-By` and `Server`, sends `HEAD`, and falls back to
`GET` only when `HEAD` returns 405 or 501. It does not follow redirects or
inspect response bodies. Missing or hidden PHP headers return `UNKNOWN`.

`OK` is a version comparison against the fixed versions from the October 21,
2026 [PHP security advisory](https://www.php.net/archive/2026.php#2026-10-21-5)
for CVE-2026-109618 and CVE-2026-109619; it does not independently verify a
security fix. PHP 8.1 and older get no upstream release, so the checker reports
them as `VULNERABLE` even where a vendor or source backport fixes them.
Headers can be hidden or changed, and distribution backports may not change the
upstream version. `UNKNOWN` does not mean the target is patched.

## Contributing

OpenAI is not accepting external code contributions to this project. Bug
reports and non-code feedback are welcome through GitHub issues. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

This project is licensed under the [Apache License 2.0](LICENSE).

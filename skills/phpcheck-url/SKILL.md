---
name: phpcheck-url
description: Check the advertised PHP version from a URL or hostname.
---

From this skill's directory, run:

```sh
node scripts/phpcheck.js "https://example.com" --json
```

Use HTTPS for a bare hostname. The checker reads `Server` and `X-Powered-By`
headers. If the version is hidden, report unknown.

The checker reports OK from the fixed versions in the October 21, 2026 PHP
advisory: 8.2.35, 8.3.36, 8.4.27 and 8.5.12. PHP 8.1 and older have no
upstream fix and report vulnerable. Headers can be changed and vendor backports
may fix an older version, so a server-side version and package check is
stronger evidence. Do not run exploit probes.

Exit codes 1 and 3 mean vulnerable and unknown, not execution failures.

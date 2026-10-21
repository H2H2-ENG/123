---
name: phpcheck-server
description: Check PHP2Shell patch status with local or server access.
---

Check the PHP version serving the site. Start with `php -v`, but verify that
it matches the site's PHP-FPM or Apache installation.

Fixed versions from the October 21, 2026
[PHP security advisory](https://www.php.net/archive/2026.php#2026-10-21-5)
for CVE-2026-109618 and CVE-2026-109619:

| PHP branch | Fixed version | Vulnerable range (inclusive) |
| --- | --- | --- |
| 5.4 to 8.1 | None upstream | All versions |
| 8.2 | 8.2.35 | 8.2.0 to 8.2.34 |
| 8.3 | 8.3.36 | 8.3.0 to 8.3.35 |
| 8.4 | 8.4.27 | 8.4.0 to 8.4.26 |
| 8.5 | 8.5.12 | 8.5.0 to 8.5.11 |

PHP 8.1 and older get no upstream release. Only a vendor or LTS package, or
PHP's source backport for 7.4, 8.0 or 8.1, can fix them; otherwise upgrade to
a fixed branch.

Compare the version and full package revision with current PHP or vendor
security advisories. Vendor backports may fix an older version. Treat unlisted
branches as unknown until an advisory confirms their status.

The running PHP build and the vendor's package advisory are the useful checks.
Configuration settings alone do not establish that PHP is patched.
Report the version, patch status, and any required update. If you cannot
verify the serving version, report unknown. Do not run exploit probes.

---
name: php2shell-triage
description: >-
  Triage, threat-hunt, and remediate PHP2Shell (CVE-2026-109618 /
  GHSA-w8hw-w9fx-j79w and CVE-2026-109619 / GHSA-6wmf-4rv5-p3rp), the critical
  unauthenticated remote-code-execution flaw in the PHP runtime. Use to
  determine whether a host or container runs a
  vulnerable PHP version across every SAPI (CLI, PHP-FPM, Apache mod_php,
  LiteSpeed/lsphp, FrankenPHP, php-cgi), to hunt for exploitation indicators in
  logs, process trees, and crash artifacts, to preserve forensic memory state,
  and to plan patching or interim mitigations. Also use when triaging
  unexplained PHP worker segfault storms, "Allowed memory size ... exhausted"
  fatals (especially "in Unknown on line 0"), or web workers spawning shells,
  even when the CVEs are not named.
---

# PHP2Shell triage, hunting & remediation

**CVEs:** [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) (OOM corruption → RCE), [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) (stale global state → use-after-free → memory disclosure and RCE), collectively **PHP2Shell**. **Severity:** Critical, CVSS v4.0 9.2 per both GitHub advisories (`AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`). Unauthenticated RCE as the web-worker account. **Affected scope:** Every PHP that serves web requests — PHP-FPM, Apache `mod_php`, LiteSpeed/`lsphp`, FrankenPHP, `php-cgi` — on PHP **5.4.0 through 8.x**. `mod_php` is the highest-risk SAPI. Confirmed `mod_php` paths run before application code; the confirmed FPM path for CVE-2026-109619 does not (§0.1). **As of:** 22 October 2026 (one day after the emergency release). The php.net news post is a summary — re-verify the two GitHub advisories before acting.

> Read this first. The only complete fix is upgrading to a fixed build (§3.1). Every interim mitigation in §3.3 is partial by the PHP team's own statement — they narrow the attack, they do not repair the bug. Absence of the indicators in §2 is **not** proof the host is clean (§4).

---

## 0. Scope and ordering

Order of operations for an estate — anything you cannot patch today comes off the internet first.

1. **Internet-facing PHP first** — every SAPI, every host, every container. `mod_php` is highest risk: confirmed exploitation runs before application code (§0.1). FPM is confirmed for CVE-2026-109619 only, and that path needs an application operation after startup.
2. Internal web-serving hosts, then staging/dev that mirrors production.
3. **Appliances, control panels, vendor products that embed PHP** — you usually cannot patch the runtime yourself; check the vendor advisories and the NCSC-NL affected-software list, and chase the vendor.
4. EOL PHP (≤ 8.1) with no vendor coverage → isolate or decommission; do not leave it internet-facing.

**Hunt window:** exploit material circulated before the 2026-10-21 patch, and details leaked around 2026-10-20. When hunting (§2), look back to at least **2026-10-13** — earlier is better — not just the last 7 days.

### 0.1 SAPI susceptibility

Both advisories. Do not treat every SAPI as the confirmed `mod_php` case, and do not clear a SAPI the advisory left unvalidated.

| SAPI | CVE-2026-109618 (OOM) | CVE-2026-109619 (stale state) |
| --- | --- | --- |
| Apache `mod_php` | Confirmed RCE before any application code, with default input and memory limits, on normal prefork. Shutdown runs even when request startup fails. Keep-alive can pin both requests of the chain to one worker. | Confirmed. PHP 8.5 fatal-backtrace path and the session-upload-progress path are both validated. On this SAPI the producer and the fatal can both happen during multipart startup, before application code. |
| PHP-FPM | Source analysis: susceptible. No complete FPM exploit has been demonstrated. FPM exits the child when request startup fails, so that startup sequence does not survive. OOM after a normal startup can still hit the bug during shutdown. | Confirmed session-lifecycle RCE on a normal dynamic pool. Startup failure kills the child, so the `mod_php` startup sequence does not apply. The validated path publishes state during application execution, fatals, then consumes it via session upload progress on a later request to the **same** worker. It depends on a suitable application operation. |
| FrankenPHP | Likely susceptible to the same application-independent shutdown path as `mod_php` (shutdown runs unconditionally). | No early INI consumer in the default configuration. Not immune — the application or an extension can still supply a consumer. |
| LiteSpeed / LSAPI | Models FPM. Application-specific exploitation is considered likely and was not validated. | Conditional. LSAPI can apply special environment INI values early. |
| `php-cgi` | No separate verdict in either advisory. The php.net summary lists it as in scope. A persistent FastCGI worker has the same "next request, same process" property as FPM. | Same. |

---

## 1. Version identification across all SAPIs

### 1.1 Fixed vs. vulnerable version matrix

| PHP branch | Vulnerable | Fixed release | Remediation path |
| --- | --- | --- | --- |
| 8.5 | `< 8.5.12` | **8.5.12** | Upgrade (active branch) |
| 8.4 | `< 8.4.27` | **8.4.27** | Upgrade (active branch) |
| 8.3 | `< 8.3.36` | **8.3.36** | Upgrade (active branch) |
| 8.2 | `< 8.2.35` | **8.2.35** | Upgrade (active branch) |
| 8.1 / 8.0 | all | no regular release (EOL) | Minimal **source backport** published for 8.1 and 8.0; or vendor LTS/ELS |
| 7.4 | all | no regular release (EOL) | Minimal **source backport** published for 7.4; or vendor ELS |
| 7.0–7.3, 5.x | all | none | No upstream backport — vendor ELS, or decommission/isolate |

Notes that matter for accuracy:

- Minimal source-level backports were provided by the PHP project for **7.4, 8.0, and 8.1 only**. Everything older (7.0–7.3, all of PHP 5) has no upstream fix.
- A version banner is not authoritative. `expose_php=Off` removes the `X-Powered-By` header, and on a compromised host the binary itself may be altered. Trust **host-local binary checks** (§1.2) over any remote banner.
- Distributions backport the fix **without bumping the upstream number** — a fully patched Ubuntu 24.04 binary still reports `8.3.6` (fixed package revision `8.3.6-0ubuntu0.24.04.13`, USN-8948-1). For distro-managed PHP the verdict is the **package revision**, compared against `references/vendor-fixes.md` — never the `php -v` number alone.

### 1.2 SAPI-aware local audit script

The assessor lives in `scripts/assess.sh` (next to this file), with unit tests in `scripts/test_assess.sh`. It is kept as a separate, tested script rather than an inline snippet so the version logic can be verified before you trust it on a host.

```bash
# Read-only. Run as root so /proc/<pid>/exe is readable for other users' workers.
bash scripts/assess.sh

# Remote host / container — pipe the whole assessor across; do NOT fall back
# to `php -v` (wrong binary possible, and distro banners hide backported fixes):
ssh root@HOST 'bash -s' < scripts/assess.sh
docker exec -i CONTAINER bash -s < scripts/assess.sh
kubectl exec -i POD -- bash -s < scripts/assess.sh

# Verify the classifier before relying on it (exit 0 = all pass):
bash scripts/test_assess.sh

# Fleet runs: the exit code is the verdict — 2 = something VULNERABLE,
# 1 = REVIEW / STALE / incomplete (not root), 0 = everything found is SECURE.
for h in web01 web02; do echo "== $h"; ssh root@$h 'bash -s' < scripts/assess.sh | tail -n1; done
```

What it does, and why this way:

- Resolves **every running web worker to its actual binary** via a `/proc` walk (no `pgrep` — the official `php:*` images do not ship procps) and reports *that* version — because the web SAPI, not the `php` in `$PATH`, is what is exposed. A host can show a patched CLI `php` while the FPM/mod_php worker serving traffic is vulnerable.
- **Reads the version without executing the binary.** PHP compiles `X-Powered-By: PHP/<version>` into every SAPI binary and `libphp*.so`; the script extracts that constant. `$exe -v` (under `timeout 5`) is only the fallback when the constant is absent — so on a suspect host the assessor is no longer running the suspect code as root.
- Classifies **distro-owned binaries via the package database** (dpkg/rpm), comparing the installed package revision against the vendor fix table (`references/vendor-fixes.md`). Third-party packages (deb.sury.org, PPAs, Remi) have a different upstream number than the archive build, so the archive's revision row is **not** applied to them — they track upstream and the upstream number decides. The banner only decides for custom/php.net builds.
- **Checks the package manifest** (`dpkg -V` / `rpm -V`): a binary that differs from what the package installed, or whose banner disagrees with its owning package, reads `REVIEW` — tampered, hand-replaced, or half-upgraded — regardless of the package revision.
- **Catches the upgrade-without-restart case.** A worker whose binary was replaced on disk after it started (`/proc/<pid>/exe` → `(deleted)`) is reported as `STALE` with the version still in memory. That is exactly the §3.1 failure mode and it never reads `SECURE`.
- **Resolves mod_php for real**: the `libphp*.so` mapped into Apache's memory (`/proc/<pid>/maps`) is classified like any other binary, including the deleted/replaced case. Apache with no `libphp` mapped (proxying to FPM) is an `INFO` row.
- **Sees containers from the host.** A worker whose binary is not the same file on this root filesystem is reported as `container <id>` with its in-memory version. Upstream/Alpine builds get a banner verdict; a container whose PHP is dpkg/rpm-managed reads `REVIEW` with the instruction to run the assessor inside it.
- Covers CLI, PHP-FPM, php-cgi, `lsphp`, FrankenPHP, mod_php, and installed-but-idle binaries under distro, source-build, cPanel/CloudLinux/Plesk/Remi and LiteSpeed paths.
- **Fails safe.** Unparseable, truncated, pre-release, or newer-than-known versions return `REVIEW` or `VULNERABLE`, never `SECURE`. A distro-suffixed version whose upstream number looks vulnerable reads `REVIEW` too — the vendor may have backported the fix, and only the package revision can answer. Not running as root prints a warning and marks the result `INCOMPLETE` (other users' workers are invisible) — the exit code is then never 0.
- Linux-oriented (uses `/proc`); it refuses to run elsewhere and prints the pipe command instead. Windows/macOS hosts: use the manual checks in §5.

### 1.3 Containers & images

**From the host first** — `assess.sh` run as root on the node lists every containerised worker it can see as `<name> (container <id> pid N)` with the version read from the running binary. That is a triage list, not a verdict for distro-based images (those rows say so); use it to find which containers to enter.

**Running container with bash** — pipe the full assessor in (it handles the Debian-base backport trap via dpkg):

```bash
docker exec -i CONTAINER bash -s < scripts/assess.sh
kubectl exec -i POD -- bash -s < scripts/assess.sh
```

**No bash (`php:*-alpine`) or no shell at all (distroless)** — `bash -s` dies there. Fall back to entrypoint override; it needs no shell, only the binary (name may be `php8`, `php83`, … depending on the image):

```bash
docker run --rm --entrypoint php     IMAGE -v
docker run --rm --entrypoint php-fpm IMAGE -v
```

Interpret the banner by base image:

- Official `php:*` images and Alpine `apk` builds compile from upstream — the banner number is the verdict.
- Debian/Ubuntu-based images backport — the banner alone cannot clear them; get bash in (sidecar, or rebuild) or scan the image's packages.

**Images not running / registry / CI** — assess what you ship, not just what runs:

```bash
docker run --rm --entrypoint php IMAGE -v      # quick check of any local image
docker pull php:8.3-fpm                        # floating tags stay STALE until pulled
trivy image IMAGE 2>/dev/null | grep -E '109618|109619'   # or: grype IMAGE
```

**Registry-wide enumeration is a scanner's job, not this script's.** Doing it properly means registry credentials, tag/manifest listing (`skopeo list-tags docker://REG/repo`), version extraction per manifest (run or layer-extract — expensive), fresh CVE↔package feeds, and mapping images to running deployments. Every registry already pairs with a scanner that maintains those feeds daily (Trivy, Grype, Docker Scout, AWS Inspector for ECR, Harbor's built-in). Point the scanner, then verify hits on the host:

```bash
# Remote image, no pull needed (uses your docker / cloud creds):
trivy image --scanners vuln REGISTRY/APP:TAG 2>/dev/null | grep -E 'CVE-2026-109618|CVE-2026-109619'
grype registry:REGISTRY/APP:TAG | grep -E '109618|109619'
# Hit → confirm on the running host (§1.2, or §1.3 above for containers),
# patch per §3.1, hunt per §2 if internet-facing.
```

---

## 2. Threat-hunting playbook

Order matters: §2.1 signals are reliably written to logs; §2.2 signals depend on logging request bodies/headers and will false-negative on a default setup.

### 2.1 Reliable crash & resource-exhaustion signals (primary)

These are emitted by PHP/the web server and do not depend on body logging. The exploit drives the runtime to exhaust memory, then corrupts it — so the **fingerprint is an OOM fatal followed by a worker segfault**, often clustered and often around multipart POST/PUT traffic.

```bash
# Out-of-memory fatals (the trigger condition for CVE-2026-109618).
#   nginx + FPM: the fatal arrives in nginx's error.log as
#   'FastCGI sent in stderr: "PHP message: PHP Fatal error: Allowed memory size…"'
grep -i "Allowed memory size of .* exhausted" \
  /var/log/php*.log /var/log/php-fpm/*.log /var/log/apache2/error.log \
  /var/log/httpd/*error*.log /var/log/nginx/*error*.log 2>/dev/null

# Worker segfaults (memory corruption surfacing as a crash)
#   PHP-FPM: "child NNN exited on signal 11 (SIGSEGV)" — Debian/Ubuntu write this
#            to /var/log/php8.x-fpm.log, RHEL to /var/log/php-fpm/error.log
#   Apache : "child pid NNN exit signal Segmentation fault (11)"
grep -Ei "exited on signal 11|SIGSEGV|exit signal Segmentation fault|segfault|signal 11" \
  /var/log/php*.log /var/log/php-fpm/*.log /var/log/apache2/error.log /var/log/httpd/*error*.log \
  /var/log/nginx/*error*.log /var/log/syslog /var/log/messages 2>/dev/null
dmesg -T 2>/dev/null | grep -Ei "php-fpm|lsphp|apache2|httpd|segfault|general protection"
journalctl -k --since "2026-10-13" 2>/dev/null | grep -Ei "segfault|php-fpm|lsphp"
# journald-managed PHP/Apache units — the file greps above never see these:
journalctl -u 'php*-fpm*' -u php-fpm -u apache2 -u httpd --since "2026-10-13" 2>/dev/null \
  | grep -Ei "Allowed memory size|signal 11|SIGSEGV|Segmentation fault|Unknown on line 0"
# Containers — logs go to the runtime (json-file driver / API), not those paths:
docker logs CONTAINER 2>&1 | grep -Ei "Allowed memory size|SIGSEGV|signal 11|Unknown on line 0"
kubectl logs POD --since=240h 2>&1 | grep -Ei "Allowed memory size|SIGSEGV|signal 11|Unknown on line 0"

# Early-startup diagnostics emitted before init ("in Unknown on line 0").
# This is the CVE-2026-109619 INI-consumer fingerprint: a warning raised
# while applying per-request INI, before php_request_startup(). It does
# not have to be fatal to be the consumer.
grep -i "in Unknown on line 0" \
  /var/log/php*.log /var/log/apache2/error.log /var/log/php-fpm/*.log 2>/dev/null
```

Also review FPM/Apache status for **bursts of worker restarts** in a short window — the DoS/crash phase of a probing or failed-exploit attempt.

CVE-2026-109619 producers are not only OOM. A fatal abandons the matching state reset; the next request on that same worker is the consumer. Ordinary application bugs match the grep below — weight clusters on internet-facing hosts, and lines sitting next to a segfault or `in Unknown on line 0`, over one parse error in a dev log.

```bash
grep -Ei "Maximum execution time of .* exceeded|PHP Parse error|PHP Fatal error:.*Uncaught" \
  /var/log/php*.log /var/log/php-fpm/*.log /var/log/apache2/error.log \
  /var/log/httpd/*error*.log /var/log/nginx/*error*.log 2>/dev/null
```

For an isolated audit, set `log_errors=On`, point `error_log` at a file the worker can write, and set `error_reporting=E_ALL` in **startup** config (`php.ini` or the FPM pool). Restart, exercise the exposed routes, then read the log for:

- deprecations and warnings repeated before the target script runs
- diagnostics during extension or server cleanup (a warning here can republish error state after shutdown already cleared it)
- fatal, parse, and uncaught errors, including a failed `require`
- `Maximum execution time exceeded`
- failures limited to an attacker-controlled route, content type, file, callback, or plugin option

Revert `E_ALL` afterward if you do not want it in production. Historical logs collected with deprecations excluded will not show the INI consumer. A failure can also happen before PHP writes the line. Empty logs are not a clean result (§4). Fixing what you find reduces exposure; it is not the patch.

### 2.2 Request-level signals (secondary — only where bodies/headers are logged)

Standard `combined`/`common` access logs record only the request line, status, size, referer, and user-agent. They do **not** contain the multipart content-type, the upload-progress field, or Content-Length/Transfer-Encoding. The greps below are useful **only** against a WAF log, a ModSecurity audit log, or an access log with an expanded format that captures bodies/headers.

```bash
# Upload-progress field name in request bodies (default field: PHP_SESSION_UPLOAD_PROGRESS)
grep -E "PHP_SESSION_UPLOAD_PROGRESS|name=\"?upload_progress" \
  /var/log/modsec_audit.log /var/log/waf/*.log 2>/dev/null

# Multipart POST/PUT/PATCH with chunked encoding or no declared length
#   (bypasses the post_max_size pre-check that reads Content-Length).
#   NOTE: uses grep -P — the negative lookahead is PCRE, not ERE (-E won't work).
grep -Pi "multipart/form-data" /var/log/modsec_audit.log 2>/dev/null \
  | grep -Pi "Transfer-Encoding: *chunked|Content-Length: *0|^(?!.*Content-Length)"

# Abnormally deep nested field names in multipart bodies (amplification: a[b][c][d]...)
grep -Eo "name=\"[^\"]*(\[[^]]*\]){4,}" /var/log/modsec_audit.log 2>/dev/null

# NOT just multipart: the demonstrated urlencoded CVE-2026-109618 shape is one
# giant field name (MBs) with control bytes in an empty-name value.
#   Regex repetition bounds cap at 255 (BSD) / 32767 (GNU ERE) / 65535 (PCRE), so
#   "{65536,}" is a hard error on every grep — measure the length with awk instead.
awk -F'&' '{ for (i = 1; i <= NF; i++) { n = index($i, "="); if (n > 65536) print FILENAME ":" FNR ": " n-1 "-byte field name" } }' \
  /var/log/modsec_audit.log /var/log/waf/*.log 2>/dev/null
#   Control bytes only (\x00-\x1f, \x7f) — NOT "non-ASCII": "café" is a legitimate
#   UTF-8 value and would false-positive on every non-English form.
grep -aP '=.*[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]' /var/log/modsec_audit.log 2>/dev/null
# High-entropy / heap-like PHPSESSID values (memory-disclosure path).
#   Needs the cookie in the log ($http_cookie / %{Cookie}i) or session.use_trans_sid —
#   a default access log has neither.
grep -E 'PHPSESSID=[A-Za-z0-9+/=]{64,}' /var/log/nginx/*access*.log /var/log/waf/*.log 2>/dev/null
```

Two CVE-2026-109618 amplification paths need the WAF to have kept part headers or filenames; the greps above do not see them otherwise:

- One multipart part may carry an unrestricted number of headers. PHP's in-memory copy costs more than the bytes on the wire, so the body can stay under `post_max_size` and still exhaust `memory_limit`. Bound the per-part header count at the frontend. PHP has no ini for it.
- Empty file controls do not count toward `max_file_uploads` and still allocate the file-metadata arrays. Nested names multiply that work. `max_file_uploads` does not close this. The limits that do are in §3.3.

### 2.3 Host, session & process inspection

```bash
# 1) Session files — may hold upload_progress_* keys or injected payloads.
#    Caveat: legitimate apps using upload progress also match (false positive);
#    a pure memory-corruption RCE may leave NO session artifact (false negative).
grep -rln "upload_progress_" /var/lib/php/sessions/ /tmp 2>/dev/null
ls -1 /tmp/sess_* /var/lib/php/sessions/sess_* 2>/dev/null
grep -a "sess_" /proc/locks 2>/dev/null        # stuck session locks (noisy)

# 2) Web workers that spawned a shell or network tool = strong post-exploit signal.
#    Join on PPID: a reverse-shell child's own args are "sh -c …" — the string
#    "php-fpm" is in the PARENT's args, so a single-line grep can never match.
for p in $(pgrep -f 'php-fpm|apache2|httpd|lsphp|frankenphp'); do
  pgrep -P "$p" -a 2>/dev/null | grep -vE 'php-fpm|apache2|httpd|lsphp|frankenphp'
done
#    Blunter and better: anything running as the web user that is not a web worker.
ps -eo pid,ppid,user,etime,comm,args | awk '$3 ~ /^(www-data|apache|nginx|nobody|http)$/' \
  | grep -vE 'php-fpm|apache2|httpd|lsphp|frankenphp'
pstree -pa "$(pgrep -x php-fpm | head -1)" 2>/dev/null

# 3) Outbound connections from web workers (reverse shells / C2 egress).
#    `ss -p` prints process NAMES, never users — grepping for "www-data" matches nothing.
#    Expect only your DB/cache/API backends; anything else (especially a public
#    peer on a high port) is egress to investigate.
ss -tnp state established 2>/dev/null | grep -Ei 'php-fpm|apache2|httpd|lsphp|frankenphp'
```

### 2.4 Preserve volatile state BEFORE restarting or patching

The use-after-free lives in worker memory; restarting or patching **wipes the evidence**. If you suspect compromise, capture a core first.

```bash
# Core dumps contain request memory — sessions, tokens, passwords of other
# requests. Root-owned, mode 700 — NOT world-readable /tmp:
install -d -m 0700 /root/php2shell_forensics
# Live core of a suspect worker (install gdb/gcore if absent)
gcore -o /root/php2shell_forensics/php_worker <PID>
# If systemd-coredump manages crashes, pull existing cores instead of losing them:
coredumpctl list 2>/dev/null
coredumpctl dump <PID-or-name> -o /root/php2shell_forensics/php_worker.core 2>/dev/null
# Confirm cores are actually being written (otherwise a crash leaves nothing).
# `ulimit -c` in YOUR shell says nothing about the worker — read the worker's limit:
cat /proc/sys/kernel/core_pattern
grep -i 'core file' "/proc/$(pgrep -x php-fpm | head -1)/limits"   # 0 = no core. FPM pool: rlimit_core; unit: LimitCORE=
# Binary integrity: assess.sh reads the version from the file without executing
# it and runs dpkg -V / rpm -V on every package-owned binary itself. Do the full
# manifest check by hand too — it covers modules and config, not just the SAPI:
dpkg -V 'php8.3-*' 'libapache2-mod-php*' 2>/dev/null || rpm -Va 'php*' 2>/dev/null
```

---

## 3. Remediation roadmap

**Patching is the only complete fix.** Do §3.1/§3.2 as the goal; use §3.3 only to reduce exposure while patching is in flight.

### 3.1 Primary: upgrade to a fixed release

- Active branches → **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35** (host packages or container base images).
- **Restart every worker** after upgrading (`systemctl restart php*-fpm`, `apache2`/`httpd`, LiteSpeed). A graceful reload that keeps old workers alive leaves the unpatched binary resident in memory.
- In containers, rebuild and redeploy — patching the host does nothing for an image that still ships a vulnerable PHP.
- **Verify, don't assume.** Re-run `scripts/assess.sh`: exit code 0, and no `STALE` rows — a `STALE` row is a worker still running the pre-upgrade binary. Then confirm the running SAPI actually loaded the settings you intended:

  ```bash
  bash scripts/assess.sh; echo "exit=$?"                     # 0 and zero STALE rows
  php-fpm8.3 -tt 2>&1 | grep -Ei 'upload_progress|memory_limit|max_requests'   # parsed pool config incl. php_admin_value
  # mod_php / anything else: a phpinfo() page served by that SAPI (ini_get reflects per-dir and admin overrides)
  ```

- **Put a finite `memory_limit` back after the upgrade** if you set `-1` while unpatched, then restart and re-run the assessor. The CVE-2026-109618 patch removes the `longjmp()` OOM bailout: OOM becomes a delayed soft failure at the next VM safe point, and a second, higher threshold hard-exits with `_exit()`. Shutdown no longer sees the invalid state, and a normal memory limit works again. Leaving `-1` keeps the unbounded-request denial of service and no longer mitigates this bug.
- If the application does not use session upload progress, leave `session.upload_progress.enabled=0` in place after the patch. [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) calls that feature hardly used and hardly tested.

### 3.2 Legacy / EOL (PHP ≤ 8.1)

- **Source backports:** apply the minimal upstream patches published for **7.4, 8.0, and 8.1** in your build pipeline. Nothing older has an upstream fix.
- **Vendor channels:** Ubuntu ESM, Debian LTS, RHEL ELS, CloudLinux, etc.
- No backport and no vendor coverage → isolate or decommission the host; do not leave it internet-facing.

### 3.3 Interim mitigations (partial — none fully block exploitation)

**CVE-2026-109619 (stale global state):** needs a producer and a consumer on the **same worker**. A fatal — OOM, parse or compile error, uncaught error, failed `require`, or `Maximum execution time exceeded` — can abandon the matching reset. A non-fatal diagnostic during later extension or server cleanup can also republish error state after shutdown already cleared it. Confirmed consumers run before normal request init.

- **Disable session upload progress:** set `session.upload_progress.enabled=0`, then **restart every worker**. It is on by default and does not need `session_start()`. It can be the producer, the consumer, or both. The application-independent trigger is OOM during input processing: on `mod_php` that can happen during multipart startup, before application code; on FPM a startup failure kills the child, so the validated path instead publishes state during application execution and consumes it on a later request (§0.1).
  - This directive is `PHP_INI_PERDIR`: `ini_set()` will **not** change it (it is read before the script runs).
  - Apply it where the application cannot override it and where the setting is not itself a per-request consumer — master `php.ini`, `php_admin_value[session.upload_progress.enabled] = 0` in the FPM pool (applied when the worker starts), or `php_admin_value session.upload_progress.enabled 0` in Apache server config.
  - Do **not** rely on FPM `.user.ini`. It is applied after normal initialization, so it neither installs this control in time nor is the early consumer.
  - On `mod_php`, `.htaccess` and directory `php_value` / `php_flag` / `php_admin_*` are applied **before** `php_request_startup()`. They can undo this control, and any diagnostic they emit is the confirmed INI consumer. Prefer server config.
  - On FPM, pool values are not the early consumer. A frontend `PHP_VALUE` / `PHP_ADMIN_VALUE` (nginx `fastcgi_param`, Apache `mod_proxy_fcgi`) that raises a diagnostic **is**. Remove those per-request parameters. Do not use them to apply this mitigation.
  - Leave the setting off after the patch if upload progress is unused.
- **PHP 8.5 only:** set `fatal_error_backtraces=0` and restart every worker. With it on, fatal-error reporting stores request-owned backtrace state and shutdown always misses the reset. This is the strongest confirmed `mod_php` case. Disabling it removes that producer only, not other global or extension state.
- **Remove per-request INI that emits a diagnostic before init.** The diagnostic does not need to be fatal, displayed, or logged. Global state is touched before PHP decides whether to report it, so `error_reporting`, `display_errors`, `log_errors`, and `@` do not help. Startup `php.ini` is not reapplied per request and is not this consumer. Settings the advisory names, to find and remove from `.htaccess`, directory config, and frontend `PHP_VALUE`:
  - Deprecations: `auto_detect_line_endings=1`; a non-default `filter.default`; PHP 8.3+ legacy `assert.*`; PHP 8.4+ legacy session settings; PHP 8.5 `report_memleaks=0` or a non-zero `intl.error_level`.
  - Explicit `mbstring.http_input`, `mbstring.http_output`, `mbstring.internal_encoding`, `iconv.input_encoding`, `iconv.output_encoding`, `iconv.internal_encoding`.
  - Invalid or conflicting `zend.assertions`, `memory_limit`, `date.timezone`, and DBA, EXIF, mail, OpenSSL, zlib, or other loaded-extension values. A per-request `memory_limit` that puts a finite value back also re-opens CVE-2026-109618; an invalid value is this consumer as well.
  - Malformed quantities (memory limit, body size, input, timeout, stack, extension values) on PHP 8.2+.
  - Log, mail, session, or SOAP cache paths rejected by `open_basedir`.
  - LSAPI can apply special environment INI early (conditional). FrankenPHP's default config has no equivalent early INI consumer; an application or extension consumer still counts.
- **No configuration mitigation covers every state family.** Other error, exception, object, and extension state depends on the application and its extensions. A fatal inside a PHP operation that calls back into the application — upload, import, error page, shutdown, destructor, serialization, output handler, plugin, extension — can publish state while that operation still holds it. Remove attacker-reachable fatals on those paths, and remove diagnostics emitted during extension post-deactivation and server cleanup. Changing `max_execution_time` only removes the timeout interruption.
- **`pm.max_requests=1` is an official partial control** when performance is acceptable. It retires the FPM worker after each request, so stale state cannot meet a later request. It does not repair the bug. `mod_php`: `MaxConnectionsPerChild 1` (Apache 2.4) is the equivalent recycling idea; the advisory names the FPM directive. Either one is expensive — scope it to exposed pools and remove it once patched.

**CVE-2026-109618 (OOM corruption):**

- **Remove the predictable OOM trigger, but add an availability boundary.** Set `memory_limit=-1` administratively, then restart every worker and confirm no pool, directory, `.htaccess`, or frontend `PHP_VALUE` puts a finite limit back.
  - **Warning:** `-1` lets one request consume unbounded memory — on its own this trades an RCE path for a **denial-of-service** path. Pair it with a container/cgroup memory limit (`memory.max`) as the availability boundary, preferably a policy that kills **only the affected worker**, not the whole pool. A cgroup limit is not guaranteed to prevent the allocation failure: `mmap()` can still fail and take the vulnerable `longjmp()` path. Killing the whole cgroup kills the master and every worker unless each worker has its own group. Killing one FPM child fails only that child's requests; the master replaces it.
  - Concretely, on systemd hosts — a drop-in on the FPM/Apache unit:

    ```ini
    # /etc/systemd/system/php8.3-fpm.service.d/php2shell.conf
    [Service]
    MemoryMax=2G          # hard ceiling for the whole pool — size it to your pool
    OOMPolicy=continue    # kernel OOM-kills the one bloated worker; the master respawns it.
                          # Default (DefaultOOMPolicy=stop) stops the WHOLE unit on any kill. systemd ≥ 243.
    ```

    `systemctl daemon-reload && systemctl restart php8.3-fpm`. Containers/pods: the container memory limit does the same job — the kernel kills the largest process in the cgroup, which is the bloated worker as long as the master stays small.
- **Never use** `RLIMIT_AS` **/** `RLIMIT_DATA` **as that boundary.** PHP's advisory warns these rlimits force mmap allocation failures — the same failure class that triggers CVE-2026-109618. Use a cgroup or container memory limit with a per-worker kill policy instead.
- **Shrink the amplification surface, at PHP and at the frontend.** A multipart body with no usable `Content-Length` can pass the `post_max_size` pre-check and keep feeding decoded data. Header blocks inside one part, nested field names, and empty file controls can exhaust `memory_limit` while the body stays inside `post_max_size`.
  - Low `post_max_size` — `8M` for apps that don't accept uploads, `32M` where uploads are required. Keep `upload_max_filesize` below `post_max_size`.
  - Reduce `max_input_nesting_level` (default 64). Bound the input-variable count with `max_input_vars`. Bound multipart part count with `max_multipart_body_parts` only on a binary whose `php -i` already lists that directive — an unknown-directive warning is a CVE-2026-109619 consumer. Empty file controls do not count toward `max_file_uploads`, so that setting does not bound them.
  - At the reverse proxy, enforce the **decoded** body size, field count, part count, per-part header count, and nesting depth, including requests with no usable `Content-Length`. If the application does not use multipart, block `multipart/form-data` before it reaches PHP.
  - These bounds also cut hard-OOM and denial-of-service risk **after** the patch. They do not replace the update.

**Defense-in-depth (not stated in the PHP advisories):**

- **Blunt mod_php's keep-alive pinning** (what lets one client hold a worker across the two-request chain): `KeepAlive Off`, or a very short `KeepAliveTimeout`. The advisories require both requests to hit the same worker; they do not name this directive. Scope it to exposed vhosts and remove it once patched. Worker recycling itself (`pm.max_requests`) is an official partial control and lives above, under CVE-2026-109619.
- **Cheap containment while unpatched: deny egress from the web user.** It does not stop the exploit, but it kills what follows it — the reverse shell and the C2/stage-2 fetch — and it turns a silent compromise into a logged connection attempt. Allow only your backends, reject the rest (adapt the CIDRs; test on one host first):

  ```bash
  # iptables: one -d per rule. Comma-separated CIDRs are an nftables set, not an iptables -d.
  # nftables equivalent: `ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } meta skuid www-data accept`
  iptables -N PHP_EGRESS
  iptables -A PHP_EGRESS -d 10.0.0.0/8       -j ACCEPT   # DB / cache / internal APIs
  iptables -A PHP_EGRESS -d 172.16.0.0/12    -j ACCEPT
  iptables -A PHP_EGRESS -d 192.168.0.0/16   -j ACCEPT
  iptables -A PHP_EGRESS -p udp --dport 53 -j ACCEPT     # DNS, if the app resolves
  iptables -A PHP_EGRESS -j LOG --log-prefix "php2shell-egress " -m limit --limit 10/min
  iptables -A PHP_EGRESS -j REJECT
  iptables -I OUTPUT -m owner --uid-owner www-data -j PHP_EGRESS
  ```

  Kubernetes: a `NetworkPolicy` with an `egress` section on the PHP pods does the same; cloud: an egress security group. Add explicit `ACCEPT`s for the external APIs the app legitimately calls before enabling.
- **At the edge, also block the §2.2 signatures the advisories do not name:** request bodies carrying `PHP_SESSION_UPLOAD_PROGRESS` (or your renamed `session.upload_progress.name`), urlencoded bodies with a field name over a few KB, and a per-source rate limit on `POST`/`PUT`. Decoded body size, missing `Content-Length`, and multipart part/header bounds are official — they sit under CVE-2026-109618 above. Low false-positive rate on most apps; verify against a day of real traffic first.
- A WAF in front (e.g. Cloudflare shipped default rules) is a shield, not a cure — treat it as buying time.

### 3.4 After suspected exposure

- Internet-facing host that stayed unpatched past **2026-10-20**: treat as exposed. Working exploit material circulated before the patch, and mass scanning followed within minutes of release.
- **Rotate everything the web-worker user could read** — database credentials in env/config files, API keys, session secrets, tokens for adjacent services. The memory-disclosure path can leak other requests' data, Heartbleed-style.
- Capture forensic state **first** (§2.4); restarting or patching wipes the evidence.
- Review `PHPSESSID` values and worker egress (§2.2, §2.3) for disclosure and post-exploit signs, and re-check after remediation.

---

## 4. Limitations & false negatives (read before reporting "clean")

- **Version coverage is only as complete as enumeration.** §1.2 covers the processes and files it can see on this host. A worker it cannot classify is printed as `REVIEW`, never dropped — but a PHP that is not running and not under a known install path (a custom prefix, a chroot, an image not deployed anywhere) is simply absent from the report. Containers appear from the host as triage rows only; run the assessor inside. `/proc/<pid>/exe`, `maps` and `root` need root for other users' processes — the report says `INCOMPLETE` otherwise.
- **mod_php is resolved from Apache's memory map** (`libphp*.so` in `/proc/<pid>/maps`), which needs root. Without it the Apache row reads `REVIEW`; confirm via a `phpinfo()` page or package metadata.
- **`STALE` means restart, not "vulnerable" and not "secure".** The row shows the version still in memory; the on-disk package may already be fixed. Restart the service and re-run — the verdict is whatever the fresh worker reports.
- **Absence of IoCs is not proof of safety.** The core of this attack is in-memory corruption — a successful exploit can leave **no disk artifact**(no webshell, no session file). Rely on crash/OOM/segfault telemetry (§2.1), WAF/body logging where available (§2.2), and the assumption that any exposed, unpatched, internet-facing host may be compromised: working exploits circulated **before** the patch and mass scanning was expected within minutes of release.
- **Body-dependent hunts under-report.** §2.2 only works where request bodies/headers are logged. On a default access-log setup those greps return nothing even under active attack.
- **Interim mitigations are partial** by the PHP team's own statement, and a PHP core developer stated the official patch is the only permanent defense. Do not report a mitigated-but-unpatched host as remediated.
- **Banners can lie.** `expose_php=Off` hides the version header; a compromised host's binary may be altered. Host-local binary checks (§1.2) outrank any remote banner.
- **SAPI verdicts are not interchangeable.** Confirmed `mod_php` exploitation of either CVE does not need application code. No complete PHP-FPM exploit of CVE-2026-109618 has been demonstrated. CVE-2026-109619 **has** been validated on FPM, and that path depends on an application operation after startup. Do not clear an FPM host because the application looks safe, and do not read "no demonstrated FPM exploit" on the OOM bug as "FPM is fine." FrankenPHP is likely on the `mod_php` shutdown path for CVE-2026-109618; its default config has no early INI consumer for CVE-2026-109619, and it is still not immune. LSAPI tracks FPM and was not validated (§0.1).
- **Log hunts miss silent failures.** The INI consumer runs before PHP decides to log. Historical `error_reporting` that dropped deprecations, `log_errors` off, or a crash before the write all look like "no indicators." The §2.1 audit settings only cover routes you actually requested.

---

## 5. Non-Linux hosts (Windows / macOS)

The vulnerability is platform-independent — the procedures are not. `assess.sh` is Linux-only and refuses elsewhere; on these hosts the checks below replace it. Same rule as everywhere: the binary that **serves the request** decides, not the CLI binary.

### Windows (IIS FastCGI, XAMPP/WAMP, Plesk)

```powershell
# Which php binary does IIS actually run (FastCGI handler mapping)?
& $env:windir\system32\inetsrv\appcmd.exe list config -section:system.webServer/fastCgi
# Version = run the DISCOVERED binary, e.g.:
& C:\php\php-cgi.exe -v
# Running workers, resolved to their real paths:
Get-Process php-cgi,php,httpd -ErrorAction SilentlyContinue | Select-Object -Unique Path
# Patched file on disk ≠ patched worker in memory: recycle after upgrading.
Restart-WebAppPool -Name <pool>      # or: iisreset
```

- Fixed Windows binaries shipped from php.net the same day (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35) — download, replace, recycle. No distro-backport trap on Windows: **the banner is the verdict again**.
- Bundled stacks patch on their own schedule — XAMPP/Bitnami, Plesk, Azure App Service, IIS Web Platform Installer. Chase the vendor.
- Worker-recycling analogs: IIS app-pool recycle interval; FastCGI `PHP_FCGI_MAX_REQUESTS` (the `pm.max_requests=1` analog).
- Crash hunt: Event Viewer → Application log, "Application Error" (Event ID 1000) with faulting module php-cgi.exe / php*.dll; IIS logs under `%SystemDrive%\inetpub\logs\LogFiles`; the PHP `error_log` path from php.ini. Windows Error Reporting `LocalDumps` is the coredump equivalent — enable it BEFORE restarting anything suspected.
- Same INI mitigations in the php.ini the SAPI loads: `session.upload_progress.enabled=0`, `memory_limit=-1`, PHP 8.5 `fatal_error_backtraces=0`. No `RLIMIT_*` on Windows; the app-pool **Private Memory limit** is the closest availability boundary (it recycles the pool, not a single worker). Per-request FastCGI environment that sets INI is the same early consumer as `PHP_VALUE` if it raises a diagnostic. Startup `php.ini` is not. Do not add a directive the binary does not know — the warning is a CVE-2026-109619 consumer.

### macOS (dev boxes, MAMP, Valet)

```bash
brew list --versions php php@8.2 php@8.3 php@8.4   # Homebrew builds
brew upgrade php && brew services restart php
# MAMP ships its own PHP inside the app bundle — update via MAMP itself:
ls /Applications/MAMP/bin/php/
# Workers actually running:
pgrep -fl 'php-fpm|php-cgi|httpd'    # Valet: valet restart
```

- No system PHP since macOS 12 — every PHP is user-installed (Homebrew, MacPorts, MAMP), so no backport trap: banner = verdict.
- Server use is rare, but a dev box port-forwarded or tunneled to the internet is an exposed web SAPI like any other.
- Crash hunt: crash reports in `~/Library/Logs/DiagnosticReports` (php*), Console.app, Homebrew/launchd service logs.

---

## 6. Sources — verify before acting

The version matrix and vendor tables go stale. The php.net news post is a summary of the two advisories below; those pages are the full text. Re-verify against:

- CVE-2026-109618 — RCE via OOM corruption: <https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w>
- CVE-2026-109619 — RCE via stale global state: <https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp>
- PHP security news (short form: fixed versions, EOL source backports, interim mitigations): <https://www.php.net/archive/2026.php#2026-10-21-5>
- NCSC-NL operational repository — detection/mitigation material and affected-software lists: <https://github.com/NCSC-NL/php2shell>
- Ubuntu fixed **package revisions** (USN-8948-1 / USN-8948-2): <https://ubuntu.com/security/notices/USN-8948-1>
- Your distro's own tracker: Debian <https://security-tracker.debian.org>, RHEL/Alma/Rocky errata, Amazon Linux ALAS, CloudLinux, Remi.
- Bundled snapshot: `references/vendor-fixes.md` 

---
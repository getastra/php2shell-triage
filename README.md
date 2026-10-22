# php2shell-triage

A defensive operational skill for finding, hunting, and remediating **PHP2Shell**— CVE-2026-109618 and CVE-2026-109619, the critical unauthenticated remote-code-execution flaws in the PHP runtime patched on 21 October 2026.

This is a detection-and-response skill. It helps a defender answer three questions on a host they own: *am I running a vulnerable PHP, has anyone tried to exploit it, and what do I do now?* It contains no exploit code.

## What's in here

| File | Purpose |
| --- | --- |
| `SKILL.md` | The skill itself: version matrix, SAPI-aware detection, IoC threat-hunting playbook, forensic capture, and the remediation roadmap. |
| `scripts/assess.sh` | Read-only version assessor. Walks `/proc` to resolve every running web worker (and the `libphp*.so` inside Apache) to its real binary, reads the version from the file without executing it, classifies distro-owned builds by package revision, checks the package manifest, flags workers still running a replaced binary (`STALE`) and containers seen from the host, and exits 2/1/0 for fleet scripting. |
| `scripts/test_assess.sh` | Unit tests for the assessor (114 cases): the version classifier, banner parsing, static version extraction, dpkg/rpm package verdicts with stubbed package tools (archive vs. third-party, same-upstream sury/PPA, same upload spine, epoch, `+dfsg`, every vendor codename, banner mismatch), the manifest-integrity override, and parity between the vendor table in the script and `references/vendor-fixes.md`. |
| `references/vendor-fixes.md` | Dated snapshot of vendor fixed-package revisions (Ubuntu USN, Debian). Distros backport without bumping the upstream number — this table is what the banner cannot tell you. Mirrored in `assess.sh`; the tests fail if the two drift. |

## Quick start

Run the assessor on a host, **as root** (so `/proc/<pid>/exe` is readable for other users' workers):

```bash
bash scripts/assess.sh
```

For remote hosts and containers, pipe the whole assessor across — don't fall back to `php -v`:

```bash
ssh root@HOST 'bash -s' < scripts/assess.sh
docker exec -i CONTAINER bash -s < scripts/assess.sh
kubectl exec -i POD -- bash -s < scripts/assess.sh
```

It prints one line per PHP it finds — CLI, PHP-FPM, php-cgi, `lsphp`, FrankenPHP, Apache `mod_php` (resolved from the process' memory map), installed-but-idle binaries, and containerised workers visible from the host — with a `SECURE` / `VULNERABLE` / `EOL_VULNERABLE` / `REVIEW` / `STALE` / `INFO` status, then a `SUMMARY:` line. For distro-owned binaries the verdict comes from the **package revision** (dpkg/rpm) against `references/vendor-fixes.md`. Third-party packages (deb.sury.org, PPAs, a self-built .deb, Remi) and custom builds are judged by upstream number, including when that number matches the archive build. `STALE` is a worker still running a binary that was replaced on disk — upgrade without restart. For images without bash (alpine/distroless), not-running images, and registry scans, see SKILL.md §1.3.

Exit code: **2** = a `VULNERABLE` or `EOL_VULNERABLE` row, including a `STALE` worker still running one of those binaries, **1** = `REVIEW`, a `STALE` worker whose in-memory version is not vulnerable, or not run as root, **0** = everything found is SECURE — so `ssh root@$h 'bash -s' < scripts/assess.sh; echo $?` is a fleet check.

Verify the classifier before you trust it:

```bash
bash scripts/test_assess.sh    # exit 0 = all pass
```

## Why a separate, tested script

The web SAPI — not the `php` in `$PATH` — is what's exposed. A host can show a patched CLI `php` while the FPM or `mod_php` worker actually serving traffic is vulnerable, so `assess.sh` checks the binary behind each running worker, not the one on `PATH`.

It does not execute the binaries it judges: PHP compiles `X-Powered-By: PHP/<version>` into every SAPI binary and `libphp*.so`, and the script reads that constant from the file (also from `/proc/<pid>/exe` after the file was deleted, and from a container's binary via `/proc/<pid>/root`). `$exe -v` under `timeout 5` is only the fallback when the constant is missing.

The classifier **fails safe**: anything unparseable, truncated, pre-release, or newer-than-known returns `REVIEW` or `VULNERABLE`, never `SECURE`. A distro-suffixed version whose upstream number looks vulnerable reads `REVIEW` too, because vendors backport the fix without bumping the number — for distro-owned binaries the verdict comes from the package database (`dpkg`/`rpm`), compared against `references/vendor-fixes.md`, and a binary that differs from its package manifest (`dpkg -V` / `rpm -V`) or disagrees with its package's version reads `REVIEW` regardless. Those edge cases are exactly what `test_assess.sh` locks down — run it after any change to the version matrix.

## Scope & limitations

- **Linux only.** `assess.sh` relies on `/proc`; it refuses to run elsewhere and prints the pipe command (`ssh root@HOST 'bash -s' < scripts/assess.sh`, `docker exec -i … bash -s`, `kubectl exec -i … -- bash -s`) for remote hosts and containers. Windows/IIS and macOS servers are not covered by the assessor — see SKILL.md §5 for the manual equivalents.
- **Log paths are Debian/Ubuntu defaults** in `SKILL.md` (e.g. `/var/log/php-fpm/`, `/var/log/apache2/`). Adjust for RHEL-family or custom layouts.
- **Absence of indicators is not proof of safety.** PHP2Shell is memory corruption; a successful exploit can leave no disk artifact. See §4 of `SKILL.md` before reporting a host clean.
- **Patching is the only complete fix.** The interim mitigations in §3.3 narrow the attack surface but do not repair the bug — treat them as a bridge to upgrading, not a substitute.

## Using it as a Claude / Cowork skill

Place the `php2shell-triage/` folder where your skills are loaded from; the skill is discovered via the `name` and `description` in `SKILL.md`'s frontmatter. It triggers on the CVE identifiers, the name "PHP2Shell," version-checking across SAPIs, and IoC hunting.

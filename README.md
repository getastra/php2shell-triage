# php2shell-triage

This skill helps a defender find PHP2Shell (CVE-2026-109618 and CVE-2026-109619), hunt for signs of exploitation, and fix it. These are critical, unauthenticated remote-code-execution flaws in the PHP runtime. PHP released the patch on 21 October 2026.

It is a detection-and-response skill, and it contains no exploit code. On a host that they own, it helps a defender answer three questions. Am I running a vulnerable PHP? Did anyone try to exploit it? What do I do now?

## What is in here

| File | Purpose |
| --- | --- |
| `SKILL.md` | The skill itself. It contains the version matrix and the detection steps for each SAPI (the server API that runs PHP). It also contains the threat-hunting playbook, forensic capture, and the remediation roadmap. |
| `scripts/assess.sh` | A read-only version assessor. It walks `/proc` to find the real binary behind every running web worker, and the `libphp*.so` inside Apache. It reads the version from the file without running it, and it classifies distro-owned builds by package revision. It compares each binary with its package manifest, and it flags workers that still run a replaced binary (`STALE`). It also reports containers seen from the host, and it exits 2, 1, or 0 for fleet scripts. |
| `scripts/test_assess.sh` | Unit tests for the assessor (114 cases). They cover the version classifier, banner parsing, and static version extraction. They also cover dpkg and rpm package verdicts, with stubbed package tools. The package cases include archive against third-party builds, same-upstream sury and PPA builds, and the same upload spine (one line of archive revisions). They also include epochs, `+dfsg`, every vendor codename, and banner mismatch. Other tests cover the manifest-integrity override, and they test that the vendor table in the script matches `references/vendor-fixes.md`. |
| `references/vendor-fixes.md` | A dated snapshot of vendor fixed-package revisions (Ubuntu USN and Debian). Distros backport the fix (apply it to the old version) without a change to the upstream number, so the banner cannot show it. This table gives that information. `assess.sh` has a copy of the table. If the two copies differ, the tests fail. |

## Quick start

Run the assessor on the host as root, because only root can read `/proc/<pid>/exe` for workers that belong to other users.

```bash
bash scripts/assess.sh
```

For a remote host or a container, pipe the whole assessor across. Do not use `php -v` instead, because it can report the wrong binary.

```bash
ssh root@HOST 'bash -s' < scripts/assess.sh
docker exec -i CONTAINER bash -s < scripts/assess.sh
kubectl exec -i POD -- bash -s < scripts/assess.sh
```

The assessor prints one line for each PHP that it finds. It covers CLI, PHP-FPM, php-cgi, `lsphp`, FrankenPHP, and Apache `mod_php`, which it resolves from the memory map of the process. It also covers installed binaries that are idle, and workers in containers that are visible from the host. Each line has a status: `SECURE`, `VULNERABLE`, `EOL_VULNERABLE`, `REVIEW`, `STALE`, or `INFO`. A `SUMMARY:` line comes last.

For dpkg-owned binaries, the verdict comes from the package revision, compared against `references/vendor-fixes.md`. For rpm-owned binaries, a fixed upstream number reads `SECURE` and any other number reads `REVIEW`, because the table has no rpm rows. For those rows, compare the package against the RHSA or ALAS advisory yourself. Third-party packages (deb.sury.org, PPAs, a self-built .deb, Remi) and custom builds get their verdict from the upstream number. The rule holds even for a package whose upstream number matches the archive build.

`STALE` means that a worker still runs an old binary. An upgrade replaced the file on disk, but nobody restarted the service. For images without bash (Alpine or distroless), images that do not run, and registry scans, see SKILL.md §1.3.

The exit code gives the worst result:

- 2: a `VULNERABLE` or `EOL_VULNERABLE` row. This includes a `STALE` worker whose in-memory version string alone reads vulnerable, for example a custom or upstream build.
- 1: a `REVIEW` row, any other `STALE` worker, a run without root, or a non-Linux host. A distro build that still runs after an upgrade without a restart is in this group. Its version string carries a package revision, so it reads `REVIEW`.
- 0: everything that the assessor found is `SECURE`.

Because of these codes, one command assesses each host in a fleet:

```bash
ssh root@$h 'bash -s' < scripts/assess.sh; echo $?
```

Before you trust the classifier, run its tests:

```bash
bash scripts/test_assess.sh    # exit 0 = all pass
```

## Why a separate, tested script

The exposed code is the web SAPI, not the `php` in `$PATH`. A host can have a patched CLI `php`, but the FPM or `mod_php` worker that serves traffic can still be vulnerable. For this reason, `assess.sh` examines the binary behind each running worker, not the binary on `PATH`.

The script does not run the binaries that it judges. PHP compiles `X-Powered-By: PHP/<version>` into every SAPI binary and into `libphp*.so`. The script reads that constant from the file. For a worker whose binary was deleted, or a worker inside a container, it reads `/proc/<pid>/exe`. It uses `/proc/<pid>/root` to reach the package database of a container.

If the constant is missing, the script runs the binary as a fallback: `$exe -v`, or `frankenphp version` for FrankenPHP. If `timeout` is installed, that run stops after 5 seconds.

The classifier fails safe, so it never guesses `SECURE`. Any version that is unparseable, truncated, a pre-release, or newer than the known releases reads `REVIEW` or `VULNERABLE`. A distro-suffixed version whose upstream number looks vulnerable also reads `REVIEW`. Vendors backport the fix without a change to the number, so the number alone cannot tell.

For dpkg-owned binaries, the package database gives the verdict, compared against `references/vendor-fixes.md`. For rpm-owned binaries, only a fixed upstream number reads `SECURE`. Some binaries differ from their package manifest (`dpkg -V` / `rpm -V`), or disagree with the version of their package. Those binaries always read `REVIEW`. `test_assess.sh` locks down these edge cases. Run it after any change to the version matrix.

## Scope and limitations

- `assess.sh` runs on Linux only, because it relies on `/proc`. On any other system, it stops and prints the pipe commands for remote hosts and containers (`ssh root@HOST 'bash -s' < scripts/assess.sh`, `docker exec -i … bash -s`). The assessor does not cover Windows/IIS or macOS servers. For the manual steps, see SKILL.md §5.
- The log paths in `SKILL.md` are distro defaults. The greps cover Debian/Ubuntu paths (`/var/log/php8.x-fpm.log`, `/var/log/apache2/`) and RHEL-family paths (`/var/log/php-fpm/`, `/var/log/httpd/`). For custom layouts, change the paths. For journald units and container logs, see SKILL.md §2.1.
- If you find no indicators, that does not prove that the host is safe. PHP2Shell is a memory-corruption flaw, and a successful exploit can leave no artifact on disk. Before you report a host as clean, read §4 of `SKILL.md`.
- Only a patch fixes the flaw completely. The interim mitigations in §3.3 make the attack surface smaller, but they do not repair the bug. Use them only until you upgrade.

## Using it as a Claude / Cowork skill

Put the `php2shell-triage/` folder where your client loads skills from. The client finds the skill through the `name` and `description` fields in the frontmatter of `SKILL.md`. The skill triggers on the CVE identifiers and the name "PHP2Shell". It also triggers on version identification across SAPIs, and on hunts for indicators of compromise (IoCs).

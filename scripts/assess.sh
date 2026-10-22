#!/usr/bin/env bash
# PHP2Shell (CVE-2026-109618 / CVE-2026-109619) exposure assessor.
#
# Reports the version of every PHP that actually serves web requests on this
# host, plus the CLI binary for reference. Read-only — changes nothing.
# Linux-only (uses /proc). Run as root: other users' /proc/<pid>/exe, maps and
# root are invisible otherwise, and the report is marked INCOMPLETE.
#
# Run it ON or IN the target (the assessor — not `php -v`: the banner can be
# the wrong binary, and distros backport fixes without bumping the number):
#   bash scripts/assess.sh
#   ssh root@HOST 'bash -s' < scripts/assess.sh
#   docker exec -i CONTAINER bash -s < scripts/assess.sh
#   kubectl exec -i POD -- bash -s < scripts/assess.sh
#
# How a verdict is reached:
#   1. The version is READ from the binary file — PHP compiles the constant
#      "X-Powered-By: PHP/<PHP_VERSION>" into every SAPI binary and libphp*.so —
#      so nothing is executed. `$exe -v` (under `timeout 5`) is the fallback
#      only when that string is absent.
#   2. Package-owned binary (dpkg/rpm) → the package REVISION decides, compared
#      against vendor_fixed_rev (mirrors references/vendor-fixes.md): Ubuntu
#      24.04's fixed build still reports 8.3.6 (package 8.3.6-0ubuntu0.24.04.13).
#      Third-party packages (deb.sury.org / PPA / a self-built .deb / Remi) do
#      not get the archive's revision verdict, even when the upstream number
#      matches (8.5.9-1+deb.sury.org+1 vs 8.5.9-0ubuntu2.1). They track
#      upstream, so the upstream number decides. The archive row applies only
#      to an archive-shaped debian revision (Nubuntu… or N~debNuN / N+debNuN).
#   3. Never SECURE from here: a binary that differs from its package manifest
#      (dpkg -V / rpm -V), a worker still running a binary that was replaced on
#      disk (STALE — upgrade without restart), a worker in another root
#      filesystem whose PHP is dpkg/rpm-managed (container — run inside).
#   4. mod_php is resolved from the Apache process' memory map (libphp*.so),
#      not guessed.
#
# Exit code: 2 = a VULNERABLE or EOL_VULNERABLE row, including a STALE worker
#            whose in-memory version is still one of those.
#            1 = REVIEW, a STALE worker whose in-memory version is not
#            vulnerable, or incomplete (not root).
#            0 = everything found is SECURE.
# Classifier functions are unit-tested by scripts/test_assess.sh — keep them in
# sync if you change the version matrix.
set -uo pipefail   # deliberately NOT -e: a benign command miss must not abort

# ---------------------------------------------------------------- classifier

# Strip epoch / revision / suffixes → bare upstream number:
#   2:8.3.6-0ubuntu0.24.04.13 → 8.3.6   5.5.9+dfsg-1ubuntu4.29+esm18 → 5.5.9
upstream_of() {
  local s="${1#*:}"
  s="${s%%-*}"; s="${s%%~*}"; s="${s%%+*}"
  printf '%s\n' "$s"
}

# Classify a version string → SECURE | VULNERABLE <fix> | EOL_VULNERABLE | REVIEW.
# Fails safe:
#   - pre-release builds (8.5.12RC1, 8.5.12-dev) never read as SECURE;
#   - distro-suffixed versions whose upstream number looks vulnerable read
#     REVIEW, because the vendor may have backported the fix into the
#     revision (see references/vendor-fixes.md) — the number alone cannot tell.
assess() {
  local v="$1" major minor patch pre=0 out f base s
  base="${v%%-*}"; base="${base%%~*}"; base="${base%%+*}"  # distro suffixes: -1ubuntu, ~deb13u1, +dfsg
  # Split on dots with parameter expansion: a here-string needs a writable
  # TMPDIR on bash < 5.1, which read-only container roots do not have.
  s="$base"
  major="${s%%.*}"; if [ "$major" = "$s" ]; then s=""; else s="${s#*.}"; fi
  minor="${s%%.*}"; if [ "$minor" = "$s" ]; then s=""; else s="${s#*.}"; fi
  patch="${s%%.*}"
  # Pre-release markers — never allow one to read as SECURE:
  #  (a) a field with letters glued on: 8.5.11RC1, 8beta
  for f in "$major" "$minor" "${patch:-}"; do
    [ -n "$f" ] && ! [[ "$f" =~ ^[0-9]+$ ]] && pre=1
  done
  #  (b) a letter-first hyphen suffix: 8.5.12-dev (distro revisions are
  #      digit-first: 8.3.6-0ubuntu0.24.04.13, 8.4.27-1~deb13u1)
  case "${1#*-}" in ""|[0-9]*) ;; *) pre=1 ;; esac
  # Cut any pre-release suffix glued to a field (8.5.11RC1 -> 11, 8beta -> 8)
  # BEFORE digit-filtering, so "11RC1" does not collapse to "111".
  major="${major%%[!0-9]*}"; minor="${minor%%[!0-9]*}"; patch="${patch%%[!0-9]*}"
  [ -z "${major:-}" ] && { echo "REVIEW (unparseable: $1)"; return; }
  : "${minor:=0}"; : "${patch:=0}"

  if [ "$major" -eq 8 ]; then
    case "$minor" in
      5) [ "$patch" -lt 12 ] && out="VULNERABLE -> 8.5.12" || out="SECURE" ;;
      4) [ "$patch" -lt 27 ] && out="VULNERABLE -> 8.4.27" || out="SECURE" ;;
      3) [ "$patch" -lt 36 ] && out="VULNERABLE -> 8.3.36" || out="SECURE" ;;
      2) [ "$patch" -lt 35 ] && out="VULNERABLE -> 8.2.35" || out="SECURE" ;;
      0|1) out="EOL_VULNERABLE (apply 8.$minor source backport or vendor LTS)" ;;
      *)   out="REVIEW (8.$minor post-dates this skill — verify upstream)" ;;
    esac
  elif [ "$major" -eq 7 ]; then
    if [ "$minor" -eq 4 ]; then
      out="EOL_VULNERABLE (apply 7.4 source backport or vendor ELS)"
    else
      out="EOL_VULNERABLE (no upstream backport — vendor ELS or decommission)"
    fi
  elif [ "$major" -lt 7 ] && [ "$major" -gt 0 ]; then
    out="EOL_VULNERABLE (no upstream backport — vendor ELS or decommission)"
  else
    out="REVIEW (PHP $v post-dates this skill — verify upstream)"
  fi

  # Fail-safe overrides:
  [ "$out" = "SECURE" ] && [ "$pre" -eq 1 ] &&
    out="REVIEW (pre-release $1 — confirm the final fixed build is installed)"
  case "$out" in
    VULNERABLE*|EOL_VULNERABLE*)
      case "$1" in
        *[-~+]*) out="REVIEW (distro package $1 — vendor may have backported the fix; compare the package revision against your vendor advisory / references/vendor-fixes.md)" ;;
      esac ;;
  esac
  echo "$out"
}

# ------------------------------------------------------------ version readers

run_timeout() { if command -v timeout >/dev/null 2>&1; then timeout 5 "$@"; else "$@"; fi; }

# Read PHP_VERSION from a binary WITHOUT executing it. Works on a path, on
# /proc/<pid>/exe (even when the file was deleted/replaced on disk), on a
# container's binary via /proc/<pid>/root/…, and on libphp*.so. No `strings`
# dependency. grep -a -m1 stops at the first match instead of rewriting the
# whole file; the class is the version token (PHP stores it as a C string).
# Busybox grep has -a, -m, -o, and -E. Do not widen the class to [^\0] —
# that does not stop at NUL, and the match would keep the "X-Powered-By:" prefix.
static_banner() {
  [ -r "$1" ] || return 0
  local v
  # `|| :` keeps a match when head closes the pipe (SIGPIPE under pipefail).
  v="$(LC_ALL=C grep -a -m1 -oE 'X-Powered-By: PHP/[0-9][0-9A-Za-z.~+-]*' -- "$1" 2>/dev/null \
        | head -n1 | sed 's|.*/||')" || :
  printf '%s\n' "$v"
}

# Pull "x.y.z[-suffix]" out of `-v` output: the first line carrying "PHP <digit>",
# wherever it sits — startup warnings ("PHP Warning: … in Unknown on line 0") may
# come first, and FrankenPHP prints "FrankenPHP v1.x PHP 8.3.14 Caddy v2.x".
# Hyphen suffixes are KEPT so 8.5.12-dev reaches the classifier as a pre-release
# and 8.1.2-1ubuntu2.14 reaches it as a distro build.
parse_banner() {
  sed -n 's/.*PHP \([0-9][0-9A-Za-z.~+-]*\).*/\1/p' | head -n1
}

# Fallback only — executes the binary (bounded by timeout 5).
exec_banner() {
  local bin="$1" sub=-v
  [ -x "$bin" ] || return 0
  case "${bin##*/}" in *frankenphp*) sub=version ;; esac
  run_timeout "$bin" "$sub" 2>&1 | parse_banner
}

banner_of() {   # banner_of <path> → version string or empty
  local b; b="$(static_banner "$1")"
  [ -n "$b" ] || b="$(exec_banner "$1")"
  printf '%s\n' "$b"
}

# ---------------------------------------------------------- package verdicts

# Vendor fixed-package revisions. Snapshot verified 2026-10-22 — vendors ship
# the fix as a REVISION without moving the upstream number, so these rows are
# the real verdict for distro-managed PHP. Mirrors references/vendor-fixes.md;
# test_assess.sh fails if the two drift. Re-verify before acting.
vendor_fixed_rev() {   # vendor_fixed_rev <branch> <release-codename> -> fixed rev or ""
  case "$1:$2" in
    php8.5:stonking) echo "8.5.9-0ubuntu2.1" ;;
    php8.5:resolute) echo "8.5.4-0ubuntu1.5" ;;
    php8.3:noble)    echo "8.3.6-0ubuntu0.24.04.13" ;;
    php8.1:jammy)    echo "8.1.2-1ubuntu2.28" ;;
    php7.4:focal)    echo "7.4.3-4ubuntu2.29+esm5" ;;
    php7.2:bionic)   echo "7.2.24-0ubuntu0.18.04.17+esm14" ;;
    php7.0:xenial)   echo "7.0.33-0ubuntu0.16.04.16+esm22" ;;
    php5:trusty)     echo "5.5.9+dfsg-1ubuntu4.29+esm18" ;;
    php8.4:trixie)   echo "8.4.27-1~deb13u1" ;;
  esac
}

# Candidate release codenames, most specific first. Derivatives (Linux Mint,
# Pop!_OS, elementary) set VERSION_CODENAME to their own name and carry the
# Ubuntu base in UBUNTU_CODENAME — try both.
os_codenames() {
  local vc="" uc=""
  # Sourced in a subshell, so assignments do not leak, but commands in the
  # file would run as this user. This is acceptable only because the operator
  # owns the host and trusts its root filesystem — an attacker who can rewrite
  # /etc/os-release is already root.
  if [ -r /etc/os-release ]; then
    read -r vc uc < <( . /etc/os-release 2>/dev/null
                       printf '%s %s\n' "${VERSION_CODENAME:-unknown}" "${UBUNTU_CODENAME:-}" )
  fi
  printf '%s %s\n' "${vc:-unknown}" "$uc"
}

# Debian revision (after the last hyphen). Epoch is ignored.
debian_revision() {
  local s="${1#*:}"
  case "$s" in
    *-*) printf '%s\n' "${s##*-}" ;;
    *) printf '\n' ;;
  esac
}

# 0 when $1 is an Ubuntu archive debian revision (1ubuntu1, 0ubuntu2.1,
# 4ubuntu2.29+esm5) or a Debian archive revision (1~deb13u1, 1+deb12u2).
# deb.sury.org, a PPA, and a plain -1 are not.
archive_debian_revision() {
  local r="$1" ure dre
  case "$r" in
    *sury*|*ppa*|*ondrej*|*remi*) return 1 ;;
  esac
  # Unquoted on purpose: bash 3.2 treats a quoted =~ operand as a literal string.
  ure='^[0-9]+ubuntu[0-9.]*[0-9]([+]esm[0-9]+)?$'
  dre='^[0-9]+[~+]deb[0-9]+u[0-9]+$'
  [[ "$r" =~ $ure ]] && return 0
  [[ "$r" =~ $dre ]] && return 0
  return 1
}

# 0 when both versions belong to the same archive family, so a
# dpkg --compare-versions against the vendor row is meaningful.
# Same upstream number is not enough: 8.5.9-1+deb.sury.org+1 and
# 8.3.6-1ppa1 share the archive's number and sort above its revision.
same_archive_lineage() {
  local a b left=0 right=0
  a="$(debian_revision "$1")"
  b="$(debian_revision "$2")"
  archive_debian_revision "$a" || return 1
  archive_debian_revision "$b" || return 1
  case "$a" in *ubuntu*) left=1 ;; esac
  case "$b" in *ubuntu*) right=1 ;; esac
  [ "$left" -eq "$right" ]
}

classify_dpkg() {   # <pkg> <installed-version> <banner-version-or-empty>
  local pkg="$1" pv="${2#*:}" banner="${3:-}" num b branch="" rel="" fixed="" fixed_num
  num="$(upstream_of "$pv")"
  # Binary/banner mismatch = replaced or half-upgraded binary — REVIEW.
  if [ -n "$banner" ]; then
    b="$(upstream_of "$banner")"
    if [ "$b" != "$num" ]; then
      echo "REVIEW (binary reports $banner but package $pkg is $pv — replaced or partially upgraded binary; verify integrity)"
      return
    fi
  fi
  # Upstream number already fixed (e.g. Debian trixie 8.4.27-1~deb13u1, sury 8.3.36)?
  case "$(assess "$num")" in
    SECURE) echo "SECURE (upstream $num fixed; $pkg $pv)"; return ;;
  esac
  [[ "$pkg" =~ (php[0-9]+(\.[0-9]+)?|php5) ]] && branch="${BASH_REMATCH[1]}"
  for rel in $(os_codenames); do
    fixed="$(vendor_fixed_rev "$branch" "$rel")"
    [ -n "$fixed" ] && break
  done
  if [ -z "$fixed" ]; then
    echo "REVIEW (distro package $pkg $pv — no fixed-revision row for '$(os_codenames)' in references/vendor-fixes.md; check your vendor advisory)"
    return
  fi
  fixed_num="$(upstream_of "$fixed")"
  # Different upstream number → not the archive package. The same number is
  # not proof either: deb.sury.org, a PPA, or a self-built .deb can share it,
  # and `dpkg --compare-versions` then ranks 8.5.9-1+deb.sury.org+1 above
  # 8.5.9-0ubuntu2.1 (and 8.3.6-1ppa1 above 8.3.6-0ubuntu0.24.04.13) — a
  # false SECURE. The archive row applies only to an archive-shaped revision.
  if [ "$num" != "$fixed_num" ] || ! same_archive_lineage "$pv" "$fixed"; then
    echo "$(assess "$num") [third-party package $pkg $pv — not the '$rel' archive build ($fixed), so the vendor revision does not apply; upstream number is the verdict]"
    return
  fi
  if dpkg --compare-versions "$pv" ge "$fixed" 2>/dev/null; then
    echo "SECURE (vendor backport: $pkg $pv >= $fixed)"
  else
    echo "VULNERABLE (distro update available: $pkg $pv < fixed $fixed — update via your package manager NOW)"
  fi
}

classify_rpm() {   # <pkg-name> <version-release> <banner-version-or-empty>
  local pkg="$1" pv="$2" banner="${3:-}" num b
  num="$(upstream_of "$pv")"
  if [ -n "$banner" ]; then
    b="$(upstream_of "$banner")"
    if [ "$b" != "$num" ]; then
      echo "REVIEW (binary reports $banner but package $pkg is $pv — replaced or partially upgraded binary; verify integrity)"
      return
    fi
  fi
  case "$(assess "$num")" in
    SECURE) echo "SECURE (upstream $num fixed; $pkg $pv)" ;;
    *) echo "REVIEW (rpm-managed $pkg $pv — verify against your vendor advisory (RHSA / ALAS / CloudLinux / Remi); see references/vendor-fixes.md)" ;;
  esac
}

# status_of <path> <banner-or-empty> → verdict. Package database first (vendors
# backport), then the package manifest check (a binary that differs from what
# dpkg/rpm installed can never be SECURE), banner last.
status_of() {
  local exe="$1" banner="${2:-}" pkg pv verdict bad
  if command -v dpkg-query >/dev/null 2>&1; then
    pkg="$(dpkg-query -S "$exe" 2>/dev/null | grep -v '^diversion' | head -n1 | cut -d: -f1 | cut -d, -f1 | tr -d ' ')"
    if [ -n "$pkg" ]; then
      pv="$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null)"
      if [ -n "$pv" ]; then
        verdict="$(classify_dpkg "$pkg" "$pv" "$banner")"
        bad="$(dpkg -V "$pkg" 2>/dev/null | awk -v f="$exe" '$NF==f')"
        [ -n "$bad" ] && verdict="REVIEW (binary $exe differs from the $pkg package manifest (dpkg -V) — tampered or hand-replaced; package verdict would be: $verdict)"
        echo "$verdict"; return
      fi
    fi
  fi
  if command -v rpm >/dev/null 2>&1; then
    if pkg="$(rpm -q --qf '%{NAME}' -f "$exe" 2>/dev/null)" && [ -n "$pkg" ]; then
      pv="$(rpm -q --qf '%{VERSION}-%{RELEASE}' "$pkg" 2>/dev/null)"
      if [ -n "$pv" ]; then
        verdict="$(classify_rpm "$pkg" "$pv" "$banner")"
        bad="$(rpm -V "$pkg" 2>/dev/null | awk -v f="$exe" '$NF==f')"
        [ -n "$bad" ] && verdict="REVIEW (binary $exe differs from the $pkg package manifest (rpm -V) — tampered or hand-replaced; package verdict would be: $verdict)"
        echo "$verdict"; return
      fi
    fi
  fi
  # Custom / php.net / source build: the banner is authoritative.
  if [ -n "$banner" ]; then
    echo "$(assess "$banner") [custom build — no package owns $exe; banner is the verdict]"
  else
    echo "REVIEW (no package owns $exe and no version string could be read from it)"
  fi
}

# When sourced (e.g. by the test harness), stop here — define functions only.
# shellcheck disable=SC2128
[ "${BASH_SOURCE[0]}" != "${0}" ] && return 0 2>/dev/null

# ------------------------------------------------------------------- report

# Executed directly: require real Linux — by uname, not /proc: Git Bash (MSYS)
# fakes /proc/self, and a near-empty report on Windows/macOS would read as
# "clean". Fail loudly instead and point at the right next step.
case "$(uname -s)" in
  Linux) ;;
  *)
    echo "ERROR: this assessor runs on Linux only — Windows/macOS hosts need the manual checks (SKILL.md §5)." >&2
    echo "  Linux remote: ssh root@HOST 'bash -s' < scripts/assess.sh" >&2
    echo "  Container:   docker exec -i CONTAINER bash -s < scripts/assess.sh" >&2
    exit 1 ;;
esac

n_vuln=0; n_review=0; n_stale=0; n_secure=0; incomplete=0
row() {   # row <label> <version> <status> — prints and tallies for the exit code
  printf '  %-34s %-24s %s\n' "$1" "${2:-?}" "$3"
  case "$3" in
    SECURE*)                     n_secure=$((n_secure+1)) ;;
    VULNERABLE*|EOL_VULNERABLE*) n_vuln=$((n_vuln+1)) ;;
    STALE*)                      n_stale=$((n_stale+1))
                                 # In-memory VULNERABLE / EOL_VULNERABLE still exits 2.
                                 case "$3" in *VULNERABLE*) n_vuln=$((n_vuln+1)) ;; esac ;;
    INFO*)                       : ;;
    *)                           n_review=$((n_review+1)) ;;
  esac
}

# Dedup set as a newline-delimited string, not an associative array: the EOL
# PHP 5.x hosts this skill cares most about run bash 3.2 / 4.1 (CentOS 5/6).
seen=$'\n'
mark_seen() {   # mark_seen <path> → 0 if new, 1 if already reported (keyed by inode when possible)
  local k; k="$(stat -Lc '%d:%i' "$1" 2>/dev/null)"; k="${k:-$1}"
  case "$seen" in *$'\n'"$k"$'\n'*) return 1 ;; esac
  seen="$seen$k"$'\n'; return 0
}

# A worker whose binary is not the same file on THIS root filesystem lives in
# another root (container seen from the host). Its binary is still readable via
# /proc/<pid>/exe; its package database is reachable via /proc/<pid>/root.
report_foreign() {   # <pid> <name> <path-inside-its-root>
  local pid="$1" name="$2" inside="$3" root="/proc/$1/root" cg v where
  # First 64-hex token: Docker (docker-<id>.scope), containerd
  # (cri-containerd-<id>.scope), CRI-O (crio-<id>.scope). A name-based runtime,
  # or a pod slice that only has a UUID, leaves this empty — the row still
  # shows the pid (`container ? pid N`).
  cg="$(grep -oE '[0-9a-f]{64}' "/proc/$pid/cgroup" 2>/dev/null | head -n1 | cut -c1-12)"
  where="container ${cg:-?} pid $pid"
  v="$(static_banner "/proc/$pid/exe")"
  if [ -z "$v" ]; then
    row "$name ($where)" "?" "REVIEW (worker in another root fs; no version string readable — run the assessor INSIDE: docker exec -i <id> bash -s < assess.sh)"
  elif [ -d "$root/var/lib/dpkg/info" ] && grep -qsFx -- "$inside" "$root"/var/lib/dpkg/info/*.list 2>/dev/null; then
    row "$name ($where)" "$v" "REVIEW (dpkg-managed PHP inside a container — the vendor may have backported; run the assessor INSIDE: docker exec -i <id> bash -s < assess.sh)"
  elif [ -d "$root/var/lib/rpm" ]; then
    row "$name ($where)" "$v" "REVIEW (rpm-based container — verify the package against the vendor advisory; run the assessor INSIDE)"
  else
    row "$name ($where)" "$v" "$(assess "$v") [container; upstream/Alpine build — banner-only verdict, the number decides]"
  fi
}

# mod_php is not a process: resolve the libphp*.so mapped into Apache from
# /proc/<pid>/maps and classify THAT file. /proc/<pid>/map_files/<range> is the
# mapped file itself, readable even after it was deleted/replaced on disk.
report_apache() {   # <pid> <name> <foreign>
  local pid="$1" name="$2" foreign="$3" range _p _o _d _i path base src v found=0 verdict done_paths="|"
  if ! [ -r "/proc/$pid/maps" ]; then
    mark_seen "/proc/$pid/exe" && row "$name (pid $pid)" "?" "REVIEW (cannot read /proc/$pid/maps to resolve mod_php — rerun as root)"
    return
  fi
  while read -r range _p _o _d _i path; do
    case "$path" in */libphp*.so|*/libphp*.so" (deleted)") ;; *) continue ;; esac
    found=1
    # One .so is mapped several times (segments); handle each path once per process.
    case "$done_paths" in *"|$path|"*) continue ;; esac
    done_paths="$done_paths$path|"
    base="${path% (deleted)}"
    src="/proc/$pid/map_files/$range"
    if ! [ -r "$src" ]; then
      case "$path" in *" (deleted)") src="" ;; *) src="/proc/$pid/root$base" ;; esac
    fi
    mark_seen "${src:-$pid:$path}" || continue
    v=""; [ -n "$src" ] && v="$(static_banner "$src")"
    [ -n "$v" ] && verdict="$(assess "$v")" || verdict="version unreadable"
    case "$path" in
      *" (deleted)")
        row "${base##*/} (mod_php in $name, pid $pid)" "$v" "STALE ($verdict in memory — libphp was replaced on disk after Apache started; restart apache2/httpd, then re-run)" ;;
      *)
        if [ "$foreign" -eq 1 ]; then
          row "${base##*/} (mod_php in $name, container pid $pid)" "$v" "$( [ -n "$v" ] && echo "$verdict" || echo REVIEW ) [container; banner-only verdict — run the assessor INSIDE]"
        else
          row "${base##*/} (mod_php in $name)" "$v" "$(status_of "$base" "$v")"
        fi ;;
    esac
  done < "/proc/$pid/maps"
  if [ "$found" -eq 0 ]; then
    mark_seen "/proc/$pid/exe" && row "$name" "-" "INFO (no mod_php mapped into Apache — proxying to FPM? confirm: apachectl -M | grep php)"
  fi
}

echo "== PHP2Shell exposure assessment =="
if [ "$(id -u)" -ne 0 ]; then
  echo "WARN: not running as root — other users' workers (/proc/<pid>/exe, maps, root) are invisible. Results are INCOMPLETE."
  incomplete=1
fi
printf '  %-34s %-24s %s\n' "SAPI / source" "version" "status"
printf '  %-34s %-24s %s\n' "----------------------------------" "------------------------" "------"

# (a) CLI php in PATH — informational; usually NOT the web version.
if command -v php >/dev/null 2>&1; then
  ex="$(readlink -f "$(command -v php)")"
  if mark_seen "$ex"; then
    v="$(banner_of "$ex")"
    row "cli (php in PATH)" "$v" "$(status_of "$ex" "$v")"
  fi
fi

# (b) Every running PHP/web process, resolved to its real binary via /proc.
#     A /proc walk needs no procps (`pgrep` is absent from the official php
#     images) and does not false-match on names (lighttpd ≠ httpd).
for p in /proc/[0-9]*; do
  pid="${p#/proc/}"
  link="$(readlink "$p/exe" 2>/dev/null)" || continue   # kernel thread, or not ours (non-root)
  [ -n "$link" ] || continue
  deleted=0
  case "$link" in *" (deleted)") deleted=1; link="${link% (deleted)}" ;; esac
  name="${link##*/}"
  case "$name" in
    php-fpm*|php*-fpm*|lsphp*|frankenphp*|php-cgi*) kind=php; label=worker ;;
    php|php[0-9]*)                                  kind=php; label=running ;;
    httpd*|apache2*)                                kind=apache ;;
    *) continue ;;
  esac
  # Same file on THIS root filesystem? Compare inodes — a path match alone lies
  # for containers (overlayfs) and for a binary replaced on disk.
  foreign=0
  if [ "$deleted" -eq 0 ]; then
    pi="$(stat -Lc '%d:%i' "$p/exe" 2>/dev/null)"; hi="$(stat -Lc '%d:%i' "$link" 2>/dev/null)"
    [ -n "$pi" ] && [ "$pi" != "${hi:-}" ] && foreign=1
  fi
  if [ "$kind" = apache ]; then
    report_apache "$pid" "$name" "$foreign"
    continue
  fi
  if [ "$deleted" -eq 1 ]; then
    mark_seen "$p/exe" || continue
    v="$(static_banner "$p/exe")"
    [ -n "$v" ] && verdict="$(assess "$v")" || verdict="version unreadable"
    row "$name ($label, e.g. pid $pid)" "$v" "STALE ($verdict in memory — the binary on disk was replaced after this worker started (upgrade without restart); restart the service, then re-run)"
    continue
  fi
  if [ "$foreign" -eq 1 ]; then
    mark_seen "$p/exe" || continue
    report_foreign "$pid" "$name" "$link"
    continue
  fi
  mark_seen "$link" || continue
  v="$(banner_of "$link")"
  row "$name ($label)" "$v" "$(status_of "$link" "$v")"
done

# (c) Installed web-SAPI binaries and mod_php modules that may be enabled but idle
#     (distro paths, source builds, cPanel/CloudLinux/Plesk/Remi/LiteSpeed stacks).
for b in /usr/sbin/php-fpm* /usr/sbin/php*-fpm /usr/bin/php-fpm* /usr/bin/php-cgi* /usr/lib/cgi-bin/php* \
         /usr/local/sbin/php-fpm* /usr/local/bin/php-fpm* /usr/local/bin/php-cgi* \
         /opt/*/sbin/php-fpm* /opt/remi/php*/root/usr/sbin/php-fpm /opt/alt/php*/usr/sbin/php-fpm \
         /opt/cpanel/ea-php*/root/usr/sbin/php-fpm /opt/plesk/php/*/sbin/php-fpm /usr/local/lsws/lsphp*/bin/lsphp \
         /usr/lib/apache2/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so /usr/lib/httpd/modules/libphp*.so \
         /usr/local/apache2/modules/libphp*.so /opt/*/modules/libphp*.so; do
  [ -f "$b" ] && [ -r "$b" ] || continue
  rb="$(readlink -f "$b")"
  mark_seen "$rb" || continue
  v="$(banner_of "$rb")"
  row "${rb##*/} (installed, idle)" "$v" "$(status_of "$rb" "$v")"
done

echo
echo "Not covered here — run the assessor ON/INSIDE each target:"
echo "  ssh root@HOST 'bash -s' < scripts/assess.sh"
echo "  docker exec -i CONTAINER bash -s < scripts/assess.sh    # rows marked 'container' above"
echo "  kubectl exec -i POD -- bash -s < scripts/assess.sh"
echo "  * Images not running anywhere: scan the registry (trivy/grype — SKILL.md §1.3)."
echo "  * A version with no patch number (e.g. '8.3') is a truncated banner — confirm before trusting."
echo
extra=""; [ "$incomplete" -eq 1 ] && extra="   INCOMPLETE (not root)"
printf 'SUMMARY: vulnerable=%d review=%d stale=%d secure=%d%s\n' "$n_vuln" "$n_review" "$n_stale" "$n_secure" "$extra"
if [ "$n_vuln" -gt 0 ]; then exit 2
elif [ $((n_review + n_stale + incomplete)) -gt 0 ]; then exit 1
else exit 0
fi

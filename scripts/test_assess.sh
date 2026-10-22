#!/usr/bin/env bash
# Unit tests for the classifier functions in assess.sh:
#   assess            version string → verdict
#   parse_banner      `-v` output → version string
#   static_banner     binary file → version string (no execution)
#   classify_dpkg     package revision + vendor table → verdict (dpkg / os_codenames stubbed)
#   classify_rpm      rpm version-release (+ banner mismatch) → verdict
#   status_of         package-manifest integrity override (dpkg-query / dpkg / rpm stubbed)
#   vendor_fixed_rev  parity with references/vendor-fixes.md
# Run: bash scripts/test_assess.sh   (exit 0 = all pass, 1 = failure)
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=assess.sh
source "$here/assess.sh"   # assess.sh returns early when sourced (defines funcs only)

pass=0; fail=0
expect() {   # expect <label> <got> <expected-substring>
  if [[ "$2" == *"$3"* ]]; then
    pass=$((pass+1))
  else
    fail=$((fail+1))
    printf 'FAIL  %s\n        got:      %s\n        expected: *%s*\n' "$1" "$2" "$3"
  fi
}
check() { expect "assess(\"$1\")" "$(assess "$1")" "$2"; }   # check <version> <expected-substring>

# ============================================================ assess()

# Active branches: boundary on each fixed version
check "8.5.12" "SECURE";                check "8.5.11" "VULNERABLE -> 8.5.12"
check "8.4.27" "SECURE";                check "8.4.26" "VULNERABLE -> 8.4.27"
check "8.3.36" "SECURE";                check "8.3.35" "VULNERABLE -> 8.3.36"
check "8.2.35" "SECURE";                check "8.2.34" "VULNERABLE -> 8.2.35"
check "8.3.36.0" "SECURE"               # four-field build number

# Pre-release builds must NEVER read as SECURE.
# Numeric below the fix stays VULNERABLE regardless of suffix (fail toward risk).
check "8.5.11RC1"    "VULNERABLE -> 8.5.12"
check "8.2.34beta"   "VULNERABLE -> 8.2.35"
check "8.5.0alpha1"  "VULNERABLE -> 8.5.12"
check "8.5.12RC1"    "REVIEW"        # RC of the fixed build — confirm, don't assume
check "8.5.12-dev"   "REVIEW"        # letter-first hyphen suffix = pre-release

# Distro-suffixed versions: the upstream number is NOT the verdict (backports).
# A vulnerable-looking distro number must read REVIEW, never VULNERABLE;
# every one of these revisions IS an official fixed package:
check "8.2.10-1ubuntu"           "REVIEW"   # generic distro banner
check "8.3.6-0ubuntu0.24.04.13"  "REVIEW"   # Ubuntu 24.04 fix (USN-8948-1)
check "8.1.2-1ubuntu2.28"        "REVIEW"   # Ubuntu 22.04 fix (USN-8948-1)
check "8.5.4-0ubuntu1.5"         "REVIEW"   # Ubuntu 26.04 fix (USN-8948-1)
check "7.4.3-4ubuntu2.29+esm5"   "REVIEW"   # Ubuntu 20.04 ESM fix (USN-8948-2)
check "5.5.9+dfsg"               "REVIEW"   # trusty esm fix path
# A distro number whose upstream is already fixed reads SECURE:
check "8.3.36-1~deb12u1"         "SECURE"
check "8.4.27-1~deb13u1"         "SECURE"   # Debian trixie fixed package

# EOL branches with / without an upstream backport (BARE upstream numbers only)
check "8.1.2"  "apply 8.1 source backport"
check "8.0.30" "apply 8.0 source backport"
check "7.4.33" "apply 7.4 source backport"
check "7.3.33" "no upstream backport"
check "5.6.40" "no upstream backport"
check "5.4.0"  "no upstream backport"

# Future branches must land in REVIEW, never SECURE (fail-safe)
check "8.6.0"  "REVIEW"
check "8.10.1" "REVIEW"
check "9.0.0"  "REVIEW"

# Garbage / empty must not fail open
check ""        "REVIEW"
check "garbage" "REVIEW"

# Truncated banners fail toward vulnerable, never secure
check "8.3" "VULNERABLE -> 8.3.36"
check "8"   "EOL_VULNERABLE"

# ====================================================== parse_banner()
# Brackets make the comparison exact ("[8.3.6]" is not a substring of "[8.3.60]").
pb() { printf '%b' "$1" | parse_banner; }
expect "parse_banner plain"          "[$(pb 'PHP 8.3.6 (cli) (built: Mar 19 2024 10:08:38) (NTS)\n')]" "[8.3.6]"
expect "parse_banner ubuntu suffix"  "[$(pb 'PHP 8.1.2-1ubuntu2.14 (cli) (built: Aug 18 2023 11:41:11) (NTS)\n')]" "[8.1.2-1ubuntu2.14]"
expect "parse_banner -dev kept"      "[$(pb 'PHP 8.5.12-dev (cli) (built: Oct  1 2026 00:00:00) (NTS)\n')]" "[8.5.12-dev]"
expect "parse_banner -dev → REVIEW"  "$(assess "$(pb 'PHP 8.5.12-dev (cli)\n')")" "REVIEW (pre-release"
expect "parse_banner startup warning first" \
  "[$(pb "PHP Warning:  PHP Startup: Unable to load dynamic library 'imagick.so' in Unknown on line 0\nPHP 8.3.6 (cli) (built: Mar 19 2024 10:08:38) (NTS)\n")]" "[8.3.6]"
expect "parse_banner frankenphp"     "[$(pb 'FrankenPHP v1.4.0 PHP 8.3.14 Caddy v2.8.4 h1:Q2hhbmdlbWU=\n')]" "[8.3.14]"
expect "parse_banner no version"     "[$(pb 'PHP Warning:  something in Unknown on line 0\n')]" "[]"
expect "parse_banner empty"          "[$(pb '')]" "[]"

# ===================================================== static_banner()
# Read from a file descriptor, no temp file: the version constant sits between NULs in a binary.
expect "static_banner finds X-Powered-By" \
  "[$(static_banner <(printf 'ELF\0garbage\0\0X-Powered-By: PHP/8.3.6-0ubuntu0.24.04.13\0more\0'))]" "[8.3.6-0ubuntu0.24.04.13]"
expect "static_banner plain upstream" \
  "[$(static_banner <(printf '\0X-Powered-By: PHP/8.4.26\0'))]" "[8.4.26]"
expect "static_banner none" \
  "[$(static_banner <(printf 'no php here\0'))]" "[]"

# ====================================================== classify_dpkg()
# Stubs: os_codenames() is overridden per scenario; dpkg --compare-versions is
# the real one on Debian/Ubuntu test hosts, a minimal token comparator elsewhere.
if ! command -v dpkg >/dev/null 2>&1; then
  _vercmp() {   # print -1 / 0 / 1; digit runs compare numerically, the rest lexically
    local -a A B; local i x y
    read -ra A < <(printf '%s\n' "$1" | sed -E 's/([0-9]+)/ \1 /g')
    read -ra B < <(printf '%s\n' "$2" | sed -E 's/([0-9]+)/ \1 /g')
    for ((i=0; i<${#A[@]} || i<${#B[@]}; i++)); do
      x="${A[i]:-}"; y="${B[i]:-}"
      [ "$x" = "$y" ] && continue
      if [[ "$x" =~ ^[0-9]+$ && "$y" =~ ^[0-9]+$ ]]; then
        (( 10#$x < 10#$y )) && echo -1 || echo 1; return
      fi
      [[ "$x" < "$y" ]] && echo -1 || echo 1; return
    done
    echo 0
  }
  dpkg() {
    [ "$1" = "--compare-versions" ] || return 2
    local r; r="$(_vercmp "$2" "$4")"
    case "$3" in ge) [ "$r" -ge 0 ] ;; gt) [ "$r" -gt 0 ] ;; le) [ "$r" -le 0 ] ;; lt) [ "$r" -lt 0 ] ;; eq) [ "$r" -eq 0 ] ;; *) return 2 ;; esac
  }
fi
TEST_CODENAMES=noble
os_codenames() { echo "$TEST_CODENAMES"; }

# Ubuntu 24.04 archive build: the REVISION decides (upstream 8.3.6 never changes)
expect "dpkg noble archive fixed .13"      "$(classify_dpkg php8.3-fpm 8.3.6-0ubuntu0.24.04.13 8.3.6)"   "SECURE (vendor backport"
expect "dpkg noble archive epoch stripped" "$(classify_dpkg php8.3-fpm 2:8.3.6-0ubuntu0.24.04.13 8.3.6)" "SECURE (vendor backport"
expect "dpkg noble archive old .12"        "$(classify_dpkg php8.3-fpm 8.3.6-0ubuntu0.24.04.12 8.3.6)"   "VULNERABLE (distro update available"
expect "dpkg mod_php package name"         "$(classify_dpkg libapache2-mod-php8.3 8.3.6-0ubuntu0.24.04.13 8.3.6)" "SECURE (vendor backport"
expect "dpkg no banner still classifies"   "$(classify_dpkg php8.3-fpm 8.3.6-0ubuntu0.24.04.13 "")"      "SECURE (vendor backport"
# Third-party (deb.sury.org) on noble: upstream number ≠ archive build → the
# archive revision row must NOT apply (a raw compare-versions would say SECURE).
expect "dpkg noble sury 8.3.35 vulnerable" "$(classify_dpkg php8.3-fpm 8.3.35-1+ubuntu24.04.1+deb.sury.org+1 8.3.35)" "VULNERABLE -> 8.3.36 [third-party package"
expect "dpkg noble sury 8.3.36 fixed"      "$(classify_dpkg php8.3-fpm 8.3.36-1+ubuntu24.04.1+deb.sury.org+1 8.3.36)" "SECURE (upstream 8.3.36 fixed"
# Binary/banner mismatch beats everything
expect "dpkg banner mismatch"              "$(classify_dpkg php8.3-fpm 8.3.36-1+ubuntu24.04.1+deb.sury.org+1 8.3.6)"  "REVIEW (binary reports 8.3.6 but package"
TEST_CODENAMES=jammy
expect "dpkg jammy archive fixed"          "$(classify_dpkg php8.1-fpm 8.1.2-1ubuntu2.28 8.1.2-1ubuntu2.28)" "SECURE (vendor backport"   # Ubuntu banners carry the revision
expect "dpkg jammy archive old"            "$(classify_dpkg php8.1-fpm 8.1.2-1ubuntu2.27 8.1.2)"           "VULNERABLE (distro update available"
expect "dpkg jammy sury 8.1 is EOL"        "$(classify_dpkg php8.1-fpm 8.1.30-1+ubuntu22.04.1+deb.sury.org+1 8.1.30)" "EOL_VULNERABLE"
TEST_CODENAMES=trusty
expect "dpkg trusty +dfsg fixed"           "$(classify_dpkg php5-fpm 5.5.9+dfsg-1ubuntu4.29+esm18 5.5.9)"  "SECURE (vendor backport"
expect "dpkg trusty +dfsg old"             "$(classify_dpkg php5-fpm 5.5.9+dfsg-1ubuntu4.29+esm17 5.5.9)"  "VULNERABLE (distro update available"
TEST_CODENAMES="wilma noble"               # Linux Mint 22: VERSION_CODENAME=wilma, UBUNTU_CODENAME=noble
expect "dpkg derivative falls back to UBUNTU_CODENAME" "$(classify_dpkg php8.3-fpm 8.3.6-0ubuntu0.24.04.13 8.3.6)" "SECURE (vendor backport"
TEST_CODENAMES=bookworm
expect "dpkg no vendor row → REVIEW"       "$(classify_dpkg php8.2-fpm 2:8.2.26-1~deb12u1 8.2.26)"        "REVIEW (distro package php8.2-fpm"
TEST_CODENAMES=trixie
expect "dpkg trixie upstream fixed"        "$(classify_dpkg php8.4-fpm 8.4.27-1~deb13u1 8.4.27)"          "SECURE (upstream 8.4.27 fixed"

# ======================================================= classify_rpm()
expect "rpm remi fixed by number"  "$(classify_rpm php-fpm 8.3.36-1.el9.remi 8.3.36)" "SECURE (upstream 8.3.36 fixed"
expect "rpm banner mismatch"       "$(classify_rpm php-fpm 8.3.36-1.el9.remi 8.3.6)"  "REVIEW (binary reports 8.3.6 but package"
expect "rpm rhel modular → REVIEW" "$(classify_rpm php-fpm 8.0.30-1.el9 8.0.30)"       "REVIEW (rpm-managed php-fpm 8.0.30-1.el9"
expect "rpm no banner → REVIEW"    "$(classify_rpm php-fpm 8.0.30-1.el9 "")"           "REVIEW (rpm-managed"

# ========================================================== status_of()
# Package-manifest integrity: a binary that differs from what dpkg installed
# can never be SECURE, even when the package revision is the fixed one.
TEST_CODENAMES=noble
dpkg-query() { case "$1" in -S) echo "php8.3-fpm: /usr/sbin/php-fpm8.3" ;; -W) echo "8.3.6-0ubuntu0.24.04.13" ;; esac; }
dpkg()       { case "$1" in -V) echo "??5??????   /usr/sbin/php-fpm8.3" ;; --compare-versions) return 0 ;; esac; }
expect "status_of tampered binary → REVIEW"    "$(status_of /usr/sbin/php-fpm8.3 8.3.6)" "REVIEW (binary /usr/sbin/php-fpm8.3 differs from the php8.3-fpm package manifest"
dpkg()       { case "$1" in -V) echo "??5?????? c /etc/php/8.3/fpm/php.ini" ;; --compare-versions) return 0 ;; esac; }
expect "status_of changed conffile ignored"    "$(status_of /usr/sbin/php-fpm8.3 8.3.6)" "SECURE (vendor backport"
dpkg()       { case "$1" in -V) : ;; --compare-versions) return 0 ;; esac; }
expect "status_of intact binary"               "$(status_of /usr/sbin/php-fpm8.3 8.3.6)" "SECURE (vendor backport"
# No package owner → banner decides; no banner → REVIEW
dpkg-query() { :; }
rpm()        { return 1; }
expect "status_of custom build vulnerable"     "$(status_of /usr/local/sbin/php-fpm 8.3.14)" "VULNERABLE -> 8.3.36 [custom build"
expect "status_of custom build fixed"          "$(status_of /usr/local/sbin/php-fpm 8.3.36)" "SECURE [custom build"
expect "status_of nothing known → REVIEW"      "$(status_of /usr/local/sbin/php-fpm "")"     "REVIEW (no package owns"
unset -f dpkg-query dpkg rpm

# ============================================ vendor table parity
# references/vendor-fixes.md is the human copy, vendor_fixed_rev() the machine
# copy. Every "| release | codename | pkg | `revision` |" row must match, and the
# function must not carry rows the document lacks.
ref="$here/../references/vendor-fixes.md"
n_ref=0
while IFS='|' read -r _ _rel code pkg rev _; do
  code="${code// /}"; pkg="${pkg// /}"; rev="${rev//[\` ]/}"
  [[ "$code" =~ ^[a-z]+$ ]] || continue       # header / separator / "plucky / questing"
  [[ "$rev"  =~ ^[0-9]     ]] || continue     # rows without a fixed revision
  n_ref=$((n_ref+1))
  expect "vendor table $pkg:$code" "[$(vendor_fixed_rev "$pkg" "$code")]" "[$rev]"
done < "$ref"
n_fn="$(grep -cE '^[[:space:]]*php[0-9.]*:[a-z]+\)[[:space:]]+echo' "$here/assess.sh")"
expect "vendor table row count (doc=$n_ref fn=$n_fn)" "[$n_fn]" "[$n_ref]"
expect "vendor table not empty" "$([ "$n_ref" -gt 0 ] && echo ok)" "ok"

echo "----------------------------------------"
echo "PASS: $pass   FAIL: $fail"
[ "$fail" -eq 0 ]

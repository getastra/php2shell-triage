#!/usr/bin/env bash
# Unit tests for the classifier functions in assess.sh:
#   assess            version string → verdict
#   parse_banner      `-v` output → version string
#   static_banner     binary file → version string (no execution)
#   classify_dpkg     package revision + vendor table → verdict (dpkg / os_codenames stubbed;
#                     same-upstream sury/PPA must not inherit the archive row)
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
# the real one on Debian/Ubuntu test hosts. Elsewhere it is Debian policy
# order (tilde before end, letters before non-letters) — ASCII order gets
# 1+ubuntu… (sury) and 1ubuntu… (archive) backwards.
if ! command -v dpkg >/dev/null 2>&1; then
  _nondigit_prefix() {
    local s="$1" o="" c
    while [ -n "$s" ]; do
      c="${s%"${s#?}"}"
      case "$c" in
        [0-9]) break ;;
        *) o="$o$c"; s="${s#?}" ;;
      esac
    done
    printf '%s\n' "$o"
  }
  _digit_prefix() {
    local s="$1" o="" c
    while [ -n "$s" ]; do
      c="${s%"${s#?}"}"
      case "$c" in
        [0-9]) o="$o$c"; s="${s#?}" ;;
        *) break ;;
      esac
    done
    printf '%s\n' "$o"
  }
  _weight() {   # Debian non-digit order: tilde < end < letters < non-letters
    case "$1" in
      '') printf '%s\n' 0 ;;
      '~') printf '%s\n' -1 ;;
      [A-Za-z]) printf '%d\n' "'$1" ;;
      *) local n; n=$(printf '%d' "'$1"); printf '%s\n' $((n + 256)) ;;
    esac
  }
  _cmp_nondigit() {
    local a="$1" b="$2" ca cb oa ob
    while [ -n "$a" ] || [ -n "$b" ]; do
      if [ -n "$a" ]; then ca="${a%"${a#?}"}"; a="${a#?}"; else ca=""; fi
      if [ -n "$b" ]; then cb="${b%"${b#?}"}"; b="${b#?}"; else cb=""; fi
      oa=$(_weight "$ca"); ob=$(_weight "$cb")
      if [ "$oa" -lt "$ob" ]; then printf '%s\n' -1; return; fi
      if [ "$oa" -gt "$ob" ]; then printf '%s\n' 1; return; fi
    done
    printf '%s\n' 0
  }
  _cmp_part() {
    local a="$1" b="$2" na nb da db c
    while [ -n "$a$b" ]; do
      na="$(_nondigit_prefix "$a")"
      nb="$(_nondigit_prefix "$b")"
      a="${a:${#na}}"
      b="${b:${#nb}}"
      c="$(_cmp_nondigit "$na" "$nb")"
      if [ "$c" -ne 0 ]; then printf '%s\n' "$c"; return; fi
      da="$(_digit_prefix "$a")"
      db="$(_digit_prefix "$b")"
      a="${a:${#da}}"
      b="${b:${#db}}"
      [ -z "$da" ] && da=0
      [ -z "$db" ] && db=0
      da=$((10#$da)); db=$((10#$db))
      if [ "$da" -lt "$db" ]; then printf '%s\n' -1; return; fi
      if [ "$da" -gt "$db" ]; then printf '%s\n' 1; return; fi
    done
    printf '%s\n' 0
  }
  _vercmp() {   # print -1 / 0 / 1. Epoch, then upstream, then debian revision.
    local ea=0 eb=0 va="$1" vb="$2" ua ub da="" db="" c
    case "$va" in *:*) ea="${va%%:*}"; va="${va#*:}" ;; esac
    case "$vb" in *:*) eb="${vb%%:*}"; vb="${vb#*:}" ;; esac
    if [ "$ea" -ne "$eb" ]; then
      if [ "$ea" -lt "$eb" ]; then printf '%s\n' -1; else printf '%s\n' 1; fi
      return
    fi
    ua="$va"; ub="$vb"
    case "$va" in *-*) da="${va##*-}"; ua="${va%-$da}" ;; esac
    case "$vb" in *-*) db="${vb##*-}"; ub="${vb%-$db}" ;; esac
    c="$(_cmp_part "$ua" "$ub")"
    if [ "$c" -ne 0 ]; then printf '%s\n' "$c"; return; fi
    _cmp_part "$da" "$db"
  }
  dpkg() {
    [ "$1" = "--compare-versions" ] || return 2
    local r; r="$(_vercmp "$2" "$4")"
    case "$3" in ge) [ "$r" -ge 0 ] ;; gt) [ "$r" -gt 0 ] ;; le) [ "$r" -le 0 ] ;; lt) [ "$r" -lt 0 ] ;; eq) [ "$r" -eq 0 ] ;; *) return 2 ;; esac
  }
fi
dpkg --compare-versions "8.1.2-1+ubuntu22.04.1+deb.sury.org+1" ge "8.1.2-1ubuntu2.28"; rc=$?
expect "vercmp jammy sury revision >= archive" "[$rc]" "[0]"
dpkg --compare-versions "5.5.9-1+ubuntu14.04.1+deb.sury.org+1" ge "5.5.9+dfsg-1ubuntu4.29+esm18"; rc=$?
expect "vercmp +dfsg upstream beats plain 5.5.9" "[$rc]" "[1]"
dpkg --compare-versions "1.0~rc1" ge "1.0"; rc=$?
expect "vercmp tilde sorts before final" "[$rc]" "[1]"
dpkg --compare-versions "1:1.0" ge "2:1.0"; rc=$?
expect "vercmp lower epoch sorts first" "[$rc]" "[1]"
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
# Same upstream number as the archive build. A raw compare-versions says SECURE.
expect "dpkg noble sury 8.3.6 same upstream" "$(classify_dpkg php8.3-fpm 8.3.6-1+ubuntu24.04.1+deb.sury.org+1 8.3.6)" "VULNERABLE -> 8.3.36 [third-party package"
expect "dpkg noble ppa 8.3.6 same upstream"  "$(classify_dpkg php8.3-fpm 8.3.6-1ppa1 8.3.6)" "VULNERABLE -> 8.3.36 [third-party package"
expect "dpkg noble self-built 8.3.6-1"      "$(classify_dpkg php8.3-fpm 8.3.6-1 8.3.6)" "VULNERABLE -> 8.3.36 [third-party package"
expect "dpkg noble archive newer .14"       "$(classify_dpkg php8.3-fpm 8.3.6-0ubuntu0.24.04.14 8.3.6)" "SECURE (vendor backport"
# Binary/banner mismatch beats everything
expect "dpkg banner mismatch"              "$(classify_dpkg php8.3-fpm 8.3.36-1+ubuntu24.04.1+deb.sury.org+1 8.3.6)"  "REVIEW (binary reports 8.3.6 but package"
TEST_CODENAMES=jammy
expect "dpkg jammy archive fixed"          "$(classify_dpkg php8.1-fpm 8.1.2-1ubuntu2.28 8.1.2-1ubuntu2.28)" "SECURE (vendor backport"   # Ubuntu banners carry the revision
expect "dpkg jammy archive old"            "$(classify_dpkg php8.1-fpm 8.1.2-1ubuntu2.27 8.1.2)"           "VULNERABLE (distro update available"
expect "dpkg jammy sury 8.1 is EOL"        "$(classify_dpkg php8.1-fpm 8.1.30-1+ubuntu22.04.1+deb.sury.org+1 8.1.30)" "EOL_VULNERABLE"
expect "dpkg jammy sury 8.1.2 same upstream" "$(classify_dpkg php8.1-fpm 8.1.2-1+ubuntu22.04.1+deb.sury.org+1 8.1.2)" "EOL_VULNERABLE (apply 8.1 source backport or vendor LTS) [third-party package"
TEST_CODENAMES=trusty
expect "dpkg trusty +dfsg fixed"           "$(classify_dpkg php5-fpm 5.5.9+dfsg-1ubuntu4.29+esm18 5.5.9)"  "SECURE (vendor backport"
expect "dpkg trusty +dfsg old"             "$(classify_dpkg php5-fpm 5.5.9+dfsg-1ubuntu4.29+esm17 5.5.9)"  "VULNERABLE (distro update available"
TEST_CODENAMES="wilma noble"               # Linux Mint 22: VERSION_CODENAME=wilma, UBUNTU_CODENAME=noble
expect "dpkg derivative falls back to UBUNTU_CODENAME" "$(classify_dpkg php8.3-fpm 8.3.6-0ubuntu0.24.04.13 8.3.6)" "SECURE (vendor backport"
TEST_CODENAMES=bookworm
expect "dpkg no vendor row → REVIEW"       "$(classify_dpkg php8.2-fpm 2:8.2.26-1~deb12u1 8.2.26)"        "REVIEW (distro package php8.2-fpm"
TEST_CODENAMES=trixie
expect "dpkg trixie upstream fixed"        "$(classify_dpkg php8.4-fpm 8.4.27-1~deb13u1 8.4.27)"          "SECURE (upstream 8.4.27 fixed"
# Backport rows whose fixed upstream number is still below the upstream fix.
# A sury/PPA package at that same number must not come out SECURE.
TEST_CODENAMES=stonking
expect "dpkg stonking archive fixed"       "$(classify_dpkg php8.5-fpm 8.5.9-0ubuntu2.1 8.5.9)" "SECURE (vendor backport"
expect "dpkg stonking archive old"         "$(classify_dpkg php8.5-fpm 8.5.9-0ubuntu2 8.5.9)" "VULNERABLE (distro update available"
expect "dpkg stonking sury 8.5.9 same upstream" "$(classify_dpkg php8.5-fpm 8.5.9-1+ubuntu26.10.1+deb.sury.org+1 8.5.9)" "VULNERABLE -> 8.5.12 [third-party package"
TEST_CODENAMES=resolute
expect "dpkg resolute archive fixed"       "$(classify_dpkg php8.5-fpm 8.5.4-0ubuntu1.5 8.5.4)" "SECURE (vendor backport"
expect "dpkg resolute archive old"         "$(classify_dpkg php8.5-fpm 8.5.4-0ubuntu1.4 8.5.4)" "VULNERABLE (distro update available"
expect "dpkg resolute sury 8.5.4 same upstream" "$(classify_dpkg php8.5-fpm 8.5.4-1+ubuntu26.04.1+deb.sury.org+1 8.5.4)" "VULNERABLE -> 8.5.12 [third-party package"
TEST_CODENAMES=focal
expect "dpkg focal archive fixed"          "$(classify_dpkg php7.4-fpm 7.4.3-4ubuntu2.29+esm5 7.4.3)" "SECURE (vendor backport"
expect "dpkg focal archive old no esm"     "$(classify_dpkg php7.4-fpm 7.4.3-4ubuntu2.29 7.4.3)" "VULNERABLE (distro update available"
expect "dpkg focal sury 7.4.3 same upstream" "$(classify_dpkg php7.4-fpm 7.4.3-1+ubuntu20.04.1+deb.sury.org+1 7.4.3)" "EOL_VULNERABLE (apply 7.4 source backport or vendor ELS) [third-party package"
TEST_CODENAMES=bionic
expect "dpkg bionic archive fixed"         "$(classify_dpkg php7.2-fpm 7.2.24-0ubuntu0.18.04.17+esm14 7.2.24)" "SECURE (vendor backport"
expect "dpkg bionic archive old"           "$(classify_dpkg php7.2-fpm 7.2.24-0ubuntu0.18.04.17+esm13 7.2.24)" "VULNERABLE (distro update available"
expect "dpkg bionic sury 7.2.24 same upstream" "$(classify_dpkg php7.2-fpm 7.2.24-1+ubuntu18.04.1+deb.sury.org+1 7.2.24)" "EOL_VULNERABLE (no upstream backport — vendor ELS or decommission) [third-party package"
TEST_CODENAMES=xenial
expect "dpkg xenial archive fixed"         "$(classify_dpkg php7.0-fpm 7.0.33-0ubuntu0.16.04.16+esm22 7.0.33)" "SECURE (vendor backport"
expect "dpkg xenial archive old"           "$(classify_dpkg php7.0-fpm 7.0.33-0ubuntu0.16.04.16+esm21 7.0.33)" "VULNERABLE (distro update available"
expect "dpkg xenial sury 7.0.33 same upstream" "$(classify_dpkg php7.0-fpm 7.0.33-1+ubuntu16.04.1+deb.sury.org+1 7.0.33)" "EOL_VULNERABLE (no upstream backport — vendor ELS or decommission) [third-party package"

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

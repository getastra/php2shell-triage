# Vendor fixed-package revisions (php2shell)

**Snapshot verified: 2026-10-22.** Vendors backport the php2shell fixes without
bumping the upstream PHP version — a fully patched Ubuntu 24.04 binary still
reports `8.3.6`. For distro-managed PHP, the **package revision** is the
verdict, not the `php -v` banner. Re-verify every row against the vendor's own
advisory before acting; this table is a convenience snapshot, not authority.

`scripts/assess.sh` carries a machine copy of this table (`vendor_fixed_rev`);
`scripts/test_assess.sh` fails if the two drift. Edit both together.

## Ubuntu (USN-8948-1 / USN-8948-2)

| Release | Codename | Source pkg | Fixed package revision (or newer) |
| --- | --- | --- | --- |
| 26.10 | stonking | php8.5 | `8.5.9-0ubuntu2.1` |
| 26.04 LTS | resolute | php8.5 | `8.5.4-0ubuntu1.5` |
| 24.04 LTS | noble | php8.3 | `8.3.6-0ubuntu0.24.04.13` |
| 22.04 LTS | jammy | php8.1 | `8.1.2-1ubuntu2.28` |
| 20.04 (ESM/Pro) | focal | php7.4 | `7.4.3-4ubuntu2.29+esm5` |
| 18.04 (ESM/Pro) | bionic | php7.2 | `7.2.24-0ubuntu0.18.04.17+esm14` |
| 16.04 (Legacy) | xenial | php7.0 | `7.0.33-0ubuntu0.16.04.16+esm22` |
| 14.04 (Legacy) | trusty | php5 | `5.5.9+dfsg-1ubuntu4.29+esm18` |
| 25.04 / 25.10 | plucky / questing | — | no fix listed; move to a supported release |

Derivatives (Linux Mint, Pop!_OS, elementary) use the Ubuntu base row —
`UBUNTU_CODENAME` in `/etc/os-release`.

Check one branch by hand (replace pkg + revision with your row). Strip the
epoch first — Debian/Ubuntu PHP packages may carry `2:`, and
`dpkg --compare-versions` would rank any epoch above the epoch-less table value:

```bash
v="$(dpkg-query -W -f='${Version}' php8.3-fpm)"; v="${v#*:}"
dpkg --compare-versions "$v" ge 8.3.6-0ubuntu0.24.04.13 && echo FIXED || echo UPDATE
```

**Only valid for the archive build.** A deb.sury.org / PPA / self-built package
tracks upstream, so the upstream number is the verdict (`>= 8.3.36` on the 8.3
branch). That includes a package whose upstream number **matches** the archive
build: `8.3.6-1+ubuntu24.04.1+deb.sury.org+1` and `8.5.9-1+deb.sury.org+1` are
not the Ubuntu backport, and a raw `dpkg --compare-versions` ranks their debian
revision above `0ubuntu…` and would wrongly call them FIXED. The same trap hits
a different Ubuntu upload at the same upstream number: `8.3.6-0ubuntu1` sorts
above `8.3.6-0ubuntu0.24.04.13`. `assess.sh` applies the archive row only on
the same upload spine as the fixed revision (`0ubuntu0.24.04.N`, `1ubuntu2.N`).

## Debian

| Release | Codename | Source pkg | Fixed package revision |
| --- | --- | --- | --- |
| 13 | trixie | php8.4 | `8.4.27-1~deb13u1` |
| 12 | bookworm | php8.2 | no DSA/DLA at snapshot time — watch <https://security-tracker.debian.org> |

## rpm-based (RHEL, Alma, Rocky, Amazon Linux, CloudLinux, Remi)

No universal table — verify against the vendor advisory:

- RHEL / Alma / Rocky: errata (RHSA) for `php` — <https://access.redhat.com/security/updates>
- Amazon Linux: ALAS — <https://alas.aws.amazon.com/>
- Remi builds track upstream numbers: banner `8.3.36`+ is fixed by number.
- Print the revision to compare: `rpm -q --qf '%{VERSION}-%{RELEASE}' php-fpm`

`assess.sh` reports REVIEW for rpm-managed installs below the upstream fix on
purpose — it does not guess vendor revision status.

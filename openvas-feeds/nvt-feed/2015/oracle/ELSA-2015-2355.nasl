# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122786");
  script_cve_id("CVE-2015-5292");
  script_tag(name:"creation_date", value:"2015-11-25 11:18:52 +0000 (Wed, 25 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2015-2355)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2355");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2355.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sssd' package(s) announced via the ELSA-2015-2355 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.13.0-40]
- Resolves: rhbz#1270827 - local overrides: don't contact server with
 overridden name/id

[1.13.0-39]
- Resolves: rhbz#1267837 - sssd_be crashed in ipa_srv_ad_acct_lookup_step

[1.13.0-38]
- Resolves: rhbz#1267176 - Memory leak / possible DoS with krb auth.

[1.13.0-37]
- Resolves: rhbz#1267836 - PAM responder crashed if user was not set

[1.13.0-36]
- Resolves: rhbz#1266107 - AD: Conditional jump or move depends on
 uninitialised value

[1.13.0-35]
- Resolves: rhbz#1250135 - Detect re-established trusts in the IPA
 subdomain code

[1.13.0-34]
- Fix a Coverity warning in dyndns code
- Resolves: rhbz#1261155 - nsupdate exits on first GSSAPI error instead
 of processing other commands

[1.13.0-33]
- Resolves: rhbz#1261155 - nsupdate exits on first GSSAPI error instead
 of processing other commands

[1.13.0-32]
- Resolves: rhbz#1263735 - Could not resolve AD user from root domain

[1.13.0-31]
- Remove -d from sss_override manpage
- Related: rhbz#1259512 - sss_override : The local override user is not found

[1.13.0-30]
- Patches required for better handling of failover with one-way trusts
- Related: rhbz#1250135 - Detect re-established trusts in the IPA subdomain
 code

[1.13.0-29]
- Resolves: rhbz#1263587 - sss_override --name doesn't work with RFC2307
 and ghost users

[1.13.0-28]
- Resolves: rhbz#1259512 - sss_override : The local override user is not found

[1.13.0-27]
- Resolves: rhbz#1260027 - sssd_be memory leak with sssd-ad in GPO code

[1.13.0-26]
- Resolves: rhbz#1256398 - sssd cannot resolve user names containing
 backslash with ldap provider

[1.13.0-25]
- Resolves: rhbz#1254189 - sss_override contains an extra parameter --debug
 but is not listed in the man page or in
 the arguments help

[1.13.0-24]
- Resolves: rhbz#1254518 - Fix crash in nss responder

[1.13.0-23]
- Support import/export for local overrides
- Support FQDNs for local overrides
- Resolves: rhbz#1254184 - sss_override does not work correctly when
 'use_fully_qualified_names = True'

[1.13.0-22]
- Resolves: rhbz#1244950 - Add index for 'objectSIDString' and maybe to
 other cache attributes

[1.13.0-21]
- Resolves: rhbz#1250415 - sssd: p11_child hardening

[1.13.0-20]
- Related: rhbz#1250135 - Detect re-established trusts in the IPA
 subdomain code

[1.13.0-19]
- Resolves: rhbz#1202724 - [RFE] Add a way to lookup users based on CAC
 identity certificates

[1.13.0-18]
- Resolves: rhbz#1232950 - [IPA/IdM] sudoOrder not honored as expected

[1.13.0-17]
- Fix wildcard_limit=0
- Resolves: rhbz#1206571 - [RFE] Expose D-BUS interface

[1.13.0-16]
- Fix race condition in invalidating the memory cache
- Related: rhbz#1206575 - [RFE] The fast memory cache should cache initgroups

[1.13.0-15]
- Resolves: rhbz#1249015 - KDC proxy not working with SSSD krb5_use_kdcinfo
 enabled

[1.13.0-14]
- Bump release number
- Related: rhbz#1246489 - sss_obfuscate fails with 'ImportError: No module
 named ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'sssd' package(s) on Oracle Linux 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac", rpm:"libipa_hbac~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac-devel", rpm:"libipa_hbac-devel~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_idmap", rpm:"libsss_idmap~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_idmap-devel", rpm:"libsss_idmap-devel~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_nss_idmap", rpm:"libsss_nss_idmap~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_nss_idmap-devel", rpm:"libsss_nss_idmap-devel~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_simpleifp", rpm:"libsss_simpleifp~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_simpleifp-devel", rpm:"libsss_simpleifp-devel~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libipa_hbac", rpm:"python-libipa_hbac~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libsss_nss_idmap", rpm:"python-libsss_nss_idmap~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-sss", rpm:"python-sss~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-sss-murmur", rpm:"python-sss-murmur~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-sssdconfig", rpm:"python-sssdconfig~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd", rpm:"sssd~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ad", rpm:"sssd-ad~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-client", rpm:"sssd-client~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-common", rpm:"sssd-common~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-common-pac", rpm:"sssd-common-pac~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-dbus", rpm:"sssd-dbus~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ipa", rpm:"sssd-ipa~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-krb5", rpm:"sssd-krb5~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-krb5-common", rpm:"sssd-krb5-common~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ldap", rpm:"sssd-ldap~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-libwbclient", rpm:"sssd-libwbclient~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-libwbclient-devel", rpm:"sssd-libwbclient-devel~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-proxy", rpm:"sssd-proxy~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-tools", rpm:"sssd-tools~1.13.0~40.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);

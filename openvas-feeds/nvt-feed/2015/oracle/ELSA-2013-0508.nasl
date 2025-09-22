# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123698");
  script_cve_id("CVE-2013-0219", "CVE-2013-0220");
  script_tag(name:"creation_date", value:"2015-10-06 11:07:23 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-0508)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0508");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0508.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sssd' package(s) announced via the ELSA-2013-0508 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.9.2-82]
- Resolves: rhbz#888614 - Failure in memberof can lead to failed
 database update

[1.9.2-81]
- Resolves: rhbz#903078 - TOCTOU race conditions by copying
 and removing directory trees

[1.9.2-80]
- Resolves: rhbz#903078 - Out-of-bounds read flaws in
 autofs and ssh services responders

[1.9.2-79]
- Resolves: rhbz#902716 - Rule mismatch isn't noticed before smart refresh
 on ppc64 and s390x

[1.9.2-78]
- Resolves: rhbz#896476 - SSSD should warn when pam_pwd_expiration_warning
 value is higher than passwordWarning LDAP attribute.

[1.9.2-77]
- Resolves: rhbz#902436 - possible segfault when backend callback is removed

[1.9.2-76]
- Resolves: rhbz#895132 - Modifications using sss_usermod tool are not
 reflected in memory cache

[1.9.2-75]
- Resolves: rhbz#894302 - sssd fails to update to changes on autofs maps

[1.9.2-74]
- Resolves: rhbz894381 - memory cache is not updated after user is deleted
 from ldb cache

[1.9.2-73]
- Resolves: rhbz895615 - ipa-client-automount: autofs failed in s390x and
 ppc64 platform

[1.9.2-72]
- Resolves: rhbz#894997 - sssd_be crashes looking up members with groups
 outside the nesting limit

[1.9.2-71]
- Resolves: rhbz#895132 - Modifications using sss_usermod tool are not
 reflected in memory cache

[1.9.2-70]
- Resolves: rhbz#894428 - wrong filter for autofs maps in sss_cache

[1.9.2-69]
- Resolves: rhbz#894738 - Failover to ldap_chpass_backup_uri doesn't work

[1.9.2-68]
- Resolves: rhbz#887961 - AD provider: getgrgid removes nested group
 memberships

[1.9.2-67]
- Resolves: rhbz#878583 - IPA Trust does not show secondary groups for AD
 Users for commands like id and getent

[1.9.2-66]
- Resolves: rhbz#874579 - sssd caching not working as expected for selinux
 usermap contexts

[1.9.2-65]
- Resolves: rhbz#892197 - Incorrect principal searched for in keytab

[1.9.2-64]
- Resolves: rhbz#891356 - Smart refresh doesn't notice 'defaults' addition
 with OpenLDAP

[1.9.2-63]
- Resolves: rhbz#878419 - sss_userdel doesn't remove entries from in-memory
 cache

[1.9.2-62]
- Resolves: rhbz#886848 - user id lookup fails for case sensitive users
 using proxy provider

[1.9.2-61]
- Resolves: rhbz#890520 - Failover to krb5_backup_kpasswd doesn't work

[1.9.2-60]
- Resolves: rhbz#874618 - sss_cache: fqdn not accepted

[1.9.2-59]
- Resolves: rhbz#889182 - crash in memory cache

[1.9.2-58]
- Resolves: rhbz#889168 - krb5 ticket renewal does not read the renewable
 tickets from cache

[1.9.2-57]
- Resolves: rhbz#886091 - Disallow root SSH public key authentication
- Add default section to switch statement (Related: rhbz#884666)

[1.9.2-56]
- Resolves: rhbz#886038 - sssd components seem to mishandle sighup

[1.9.2-55]
- Resolves: rhbz#888800 - Memory leak in new memcache initgr cleanup function

[1.9.2-54]
- Resolves: rhbz#888614 - Failure in memberof can lead to failed database
 update

[1.9.2-53]
- Resolves: rhbz#885078 - sssd_nss crashes during ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'sssd' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac", rpm:"libipa_hbac~1.9.2~82.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac-devel", rpm:"libipa_hbac-devel~1.9.2~82.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac-python", rpm:"libipa_hbac-python~1.9.2~82.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_autofs", rpm:"libsss_autofs~1.9.2~82.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_idmap", rpm:"libsss_idmap~1.9.2~82.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_idmap-devel", rpm:"libsss_idmap-devel~1.9.2~82.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_sudo", rpm:"libsss_sudo~1.9.2~82.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_sudo-devel", rpm:"libsss_sudo-devel~1.9.2~82.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd", rpm:"sssd~1.9.2~82.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-client", rpm:"sssd-client~1.9.2~82.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-tools", rpm:"sssd-tools~1.9.2~82.el6", rls:"OracleLinux6"))) {
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

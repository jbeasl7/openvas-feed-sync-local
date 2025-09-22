# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122731");
  script_cve_id("CVE-2015-5292");
  script_tag(name:"creation_date", value:"2015-11-11 07:59:50 +0000 (Wed, 11 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2015-2019)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2019");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2019.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sssd' package(s) announced via the ELSA-2015-2019 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.12.4-47.4]
- Resolves: rhbz#1268783 - Memory leak / possible DoS with krb auth.

[1.12.4-47.3]
- Resolves: rhbz#1268784 - SSSD POSIX attribute check is too strict

[1.12.4-47.2]
- Resolves: rhbz#1264098 - cleanup_groups should sanitize dn of groups

[1.12.4-47.1]
- Resolves: rhbz#1258398 - sysdb sudo search doesn't escape special
 characters");

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

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac", rpm:"libipa_hbac~1.12.4~47.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac-devel", rpm:"libipa_hbac-devel~1.12.4~47.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac-python", rpm:"libipa_hbac-python~1.12.4~47.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_idmap", rpm:"libsss_idmap~1.12.4~47.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_idmap-devel", rpm:"libsss_idmap-devel~1.12.4~47.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_nss_idmap", rpm:"libsss_nss_idmap~1.12.4~47.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_nss_idmap-devel", rpm:"libsss_nss_idmap-devel~1.12.4~47.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_nss_idmap-python", rpm:"libsss_nss_idmap-python~1.12.4~47.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_simpleifp", rpm:"libsss_simpleifp~1.12.4~47.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_simpleifp-devel", rpm:"libsss_simpleifp-devel~1.12.4~47.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-sssdconfig", rpm:"python-sssdconfig~1.12.4~47.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd", rpm:"sssd~1.12.4~47.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ad", rpm:"sssd-ad~1.12.4~47.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-client", rpm:"sssd-client~1.12.4~47.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-common", rpm:"sssd-common~1.12.4~47.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-common-pac", rpm:"sssd-common-pac~1.12.4~47.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-dbus", rpm:"sssd-dbus~1.12.4~47.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ipa", rpm:"sssd-ipa~1.12.4~47.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-krb5", rpm:"sssd-krb5~1.12.4~47.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-krb5-common", rpm:"sssd-krb5-common~1.12.4~47.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ldap", rpm:"sssd-ldap~1.12.4~47.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-proxy", rpm:"sssd-proxy~1.12.4~47.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-tools", rpm:"sssd-tools~1.12.4~47.el6_7.4", rls:"OracleLinux6"))) {
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

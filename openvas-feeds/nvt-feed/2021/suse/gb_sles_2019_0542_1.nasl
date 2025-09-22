# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0542.1");
  script_cve_id("CVE-2019-3811");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:30 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-01 17:06:40 +0000 (Fri, 01 Feb 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0542-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0542-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190542-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sssd' package(s) announced via the SUSE-SU-2019:0542-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for sssd fixes the following issues:

Security vulnerability addresed:
CVE-2019-3811: Fix fallback_homedir returning '/' for empty home
 directories (bsc#1121759)

Other bug fixes and changes:
Install logrotate configuration (bsc#1004220)

Align systemd service file with upstream, run interactive and change
 service type to notify (bsc#1120852)

Fix sssd not starting in foreground mode (bsc#1125277)

Strip whitespaces in netgroup triples (bsc#1087320)");

  script_tag(name:"affected", value:"'sssd' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac-devel", rpm:"libipa_hbac-devel~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac0", rpm:"libipa_hbac0~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac0-debuginfo", rpm:"libipa_hbac0-debuginfo~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_certmap-devel", rpm:"libsss_certmap-devel~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_certmap0", rpm:"libsss_certmap0~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_certmap0-debuginfo", rpm:"libsss_certmap0-debuginfo~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_idmap-devel", rpm:"libsss_idmap-devel~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_idmap0", rpm:"libsss_idmap0~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_idmap0-debuginfo", rpm:"libsss_idmap0-debuginfo~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_nss_idmap-devel", rpm:"libsss_nss_idmap-devel~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_nss_idmap0", rpm:"libsss_nss_idmap0~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_nss_idmap0-debuginfo", rpm:"libsss_nss_idmap0-debuginfo~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_simpleifp-devel", rpm:"libsss_simpleifp-devel~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_simpleifp0", rpm:"libsss_simpleifp0~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_simpleifp0-debuginfo", rpm:"libsss_simpleifp0-debuginfo~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-sssd-config", rpm:"python3-sssd-config~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-sssd-config-debuginfo", rpm:"python3-sssd-config-debuginfo~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd", rpm:"sssd~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-32bit", rpm:"sssd-32bit~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-32bit-debuginfo", rpm:"sssd-32bit-debuginfo~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ad", rpm:"sssd-ad~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ad-debuginfo", rpm:"sssd-ad-debuginfo~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-dbus", rpm:"sssd-dbus~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-dbus-debuginfo", rpm:"sssd-dbus-debuginfo~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-debuginfo", rpm:"sssd-debuginfo~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-debugsource", rpm:"sssd-debugsource~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ipa", rpm:"sssd-ipa~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ipa-debuginfo", rpm:"sssd-ipa-debuginfo~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-krb5", rpm:"sssd-krb5~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-krb5-common", rpm:"sssd-krb5-common~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-krb5-common-debuginfo", rpm:"sssd-krb5-common-debuginfo~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-krb5-debuginfo", rpm:"sssd-krb5-debuginfo~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ldap", rpm:"sssd-ldap~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ldap-debuginfo", rpm:"sssd-ldap-debuginfo~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-proxy", rpm:"sssd-proxy~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-proxy-debuginfo", rpm:"sssd-proxy-debuginfo~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-tools", rpm:"sssd-tools~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-tools-debuginfo", rpm:"sssd-tools-debuginfo~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-wbclient", rpm:"sssd-wbclient~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-wbclient-debuginfo", rpm:"sssd-wbclient-debuginfo~1.16.1~3.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-wbclient-devel", rpm:"sssd-wbclient-devel~1.16.1~3.15.1", rls:"SLES15.0"))) {
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

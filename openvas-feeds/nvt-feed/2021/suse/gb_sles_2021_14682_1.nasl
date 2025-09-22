# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.14682.1");
  script_cve_id("CVE-2020-28243", "CVE-2020-28972", "CVE-2020-35662", "CVE-2021-25281", "CVE-2021-25282", "CVE-2021-25283", "CVE-2021-25284", "CVE-2021-3144", "CVE-2021-3148", "CVE-2021-3197");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:41 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-05 14:38:41 +0000 (Fri, 05 Mar 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:14682-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:14682-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-202114682-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE Manager Client Tools' package(s) announced via the SUSE-SU-2021:14682-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

mgr-osad:

Adapt to new SSL implementation of rhnlib (bsc#1181807)

rhnlib:

Change SSL implementation to python ssl for better SAN and hostname
 matching support (bsc#1181807)

salt:

Do not crash when unexpected cmd output at listing patches (bsc#1181290)

Fix regression on cmd.run when passing tuples as cmd (bsc#1182740)

Allow extra_filerefs as sanitized kwargs for SSH client

Fix for multiple for security issues (CVE-2020-28243) (CVE-2020-28972)
 (CVE-2020-35662) (CVE-2021-3148) (CVE-2021-3144) (CVE-2021-25281)
 (CVE-2021-25282) (CVE-2021-25283) (CVE-2021-25284) (CVE-2021-3197)
 (bsc#1181550) (bsc#1181556) (bsc#1181557) (bsc#1181558) (bsc#1181559)
 (bsc#1181560) (bsc#1181561) (bsc#1181562) (bsc#1181563) (bsc#1181564)
 (bsc#1181565)

spacewalk-client-tools:

Fallback to sysfs when reading info from python-dmidecode fails
 (bsc#1182603)

Log an error when product detection failed (bsc#1182339)

Adapt to new SSL implementation of rhnlib (bsc#1181807)");

  script_tag(name:"affected", value:"'SUSE Manager Client Tools' package(s) on SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"mgr-osad", rpm:"mgr-osad~4.2.3~8.12.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-osa-common", rpm:"python2-mgr-osa-common~4.2.3~8.12.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-osad", rpm:"python2-mgr-osad~4.2.3~8.12.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-rhnlib", rpm:"python2-rhnlib~4.2.2~15.12.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-check", rpm:"python2-spacewalk-check~4.2.7~30.24.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-client-setup", rpm:"python2-spacewalk-client-setup~4.2.7~30.24.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-client-tools", rpm:"python2-spacewalk-client-tools~4.2.7~30.24.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~2016.11.10~46.15.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~2016.11.10~46.15.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~2016.11.10~46.15.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-check", rpm:"spacewalk-check~4.2.7~30.24.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-client-setup", rpm:"spacewalk-client-setup~4.2.7~30.24.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-client-tools", rpm:"spacewalk-client-tools~4.2.7~30.24.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"mgr-osad", rpm:"mgr-osad~4.2.3~8.12.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-osa-common", rpm:"python2-mgr-osa-common~4.2.3~8.12.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-osad", rpm:"python2-mgr-osad~4.2.3~8.12.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-rhnlib", rpm:"python2-rhnlib~4.2.2~15.12.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-check", rpm:"python2-spacewalk-check~4.2.7~30.24.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-client-setup", rpm:"python2-spacewalk-client-setup~4.2.7~30.24.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-client-tools", rpm:"python2-spacewalk-client-tools~4.2.7~30.24.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~2016.11.10~46.15.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~2016.11.10~46.15.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~2016.11.10~46.15.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-check", rpm:"spacewalk-check~4.2.7~30.24.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-client-setup", rpm:"spacewalk-client-setup~4.2.7~30.24.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-client-tools", rpm:"spacewalk-client-tools~4.2.7~30.24.1", rls:"SLES11.0SP4"))) {
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

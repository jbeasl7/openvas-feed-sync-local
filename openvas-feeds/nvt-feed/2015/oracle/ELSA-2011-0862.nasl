# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122150");
  script_cve_id("CVE-2011-1752", "CVE-2011-1783", "CVE-2011-1921");
  script_tag(name:"creation_date", value:"2015-10-06 11:13:54 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2011-0862)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-0862");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-0862.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'subversion' package(s) announced via the ELSA-2011-0862 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.6.11-2.4]
- add security fixes for CVE-2011-1752, CVE-2011-1783, CVE-2011-1921 (#709220)");

  script_tag(name:"affected", value:"'subversion' package(s) on Oracle Linux 5, Oracle Linux 6.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"mod_dav_svn", rpm:"mod_dav_svn~1.6.11~7.el5_6.4", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion", rpm:"subversion~1.6.11~7.el5_6.4", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-devel", rpm:"subversion-devel~1.6.11~7.el5_6.4", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-javahl", rpm:"subversion-javahl~1.6.11~7.el5_6.4", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-perl", rpm:"subversion-perl~1.6.11~7.el5_6.4", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-ruby", rpm:"subversion-ruby~1.6.11~7.el5_6.4", rls:"OracleLinux5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"mod_dav_svn", rpm:"mod_dav_svn~1.6.11~2.el6_1.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion", rpm:"subversion~1.6.11~2.el6_1.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-devel", rpm:"subversion-devel~1.6.11~2.el6_1.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-gnome", rpm:"subversion-gnome~1.6.11~2.el6_1.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-javahl", rpm:"subversion-javahl~1.6.11~2.el6_1.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-kde", rpm:"subversion-kde~1.6.11~2.el6_1.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-perl", rpm:"subversion-perl~1.6.11~2.el6_1.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-ruby", rpm:"subversion-ruby~1.6.11~2.el6_1.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-svn2cl", rpm:"subversion-svn2cl~1.6.11~2.el6_1.4", rls:"OracleLinux6"))) {
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

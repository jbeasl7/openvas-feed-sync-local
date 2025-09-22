# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123468");
  script_cve_id("CVE-2013-5908", "CVE-2014-0001", "CVE-2014-0386", "CVE-2014-0393", "CVE-2014-0401", "CVE-2014-0402", "CVE-2014-0412", "CVE-2014-0437");
  script_tag(name:"creation_date", value:"2015-10-06 11:04:12 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2014-0164)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-0164");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-0164.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.1/en/news-5-1-73.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql' package(s) announced via the ELSA-2014-0164 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[5.1.73-3]
- Fixes for CVE-2014-0001
 Resolves: #1055880

[5.1.73-2]
- Make mysqld init script more robust and ignore existing but
 non-being-used unix socket file
 Resolves: #1058719

[5.1.73-1]
- Update to MySQL 5.1.73, for various fixes described at
 [link moved to references]
 (CVE-2014-0412, CVE-2014-0437, CVE-2013-5908, CVE-2014-0393,
 CVE-2014-0386, CVE-2014-0401, CVE-2014-0402)
 Resolves: #1055880");

  script_tag(name:"affected", value:"'mysql' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.1.73~3.el6_5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~5.1.73~3.el6_5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-devel", rpm:"mysql-devel~5.1.73~3.el6_5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-embedded", rpm:"mysql-embedded~5.1.73~3.el6_5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-embedded-devel", rpm:"mysql-embedded-devel~5.1.73~3.el6_5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-libs", rpm:"mysql-libs~5.1.73~3.el6_5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-server", rpm:"mysql-server~5.1.73~3.el6_5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-test", rpm:"mysql-test~5.1.73~3.el6_5", rls:"OracleLinux6"))) {
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

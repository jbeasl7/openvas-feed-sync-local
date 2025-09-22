# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123757");
  script_cve_id("CVE-2012-4452");
  script_tag(name:"creation_date", value:"2015-10-06 11:08:08 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Oracle: Security Advisory (ELSA-2013-0121)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0121");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0121.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql' package(s) announced via the ELSA-2013-0121 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[5.0.95-3]
- Re-add patch for CVE-2009-4030, mistakenly removed in 5.0.95 rebase
Resolves: CVE-2012-4452

[5.0.95-2]
- Support rotation of mysqld log (though this is not enabled by default)
Resolves: #647223
- Fix crash with EXPLAIN and prepared statements
Resolves: #654000
- Adopt init script updates from the last Fedora init script (F-15)
Resolves: #703476");

  script_tag(name:"affected", value:"'mysql' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.0.95~3.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~5.0.95~3.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-devel", rpm:"mysql-devel~5.0.95~3.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-server", rpm:"mysql-server~5.0.95~3.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-test", rpm:"mysql-test~5.0.95~3.el5", rls:"OracleLinux5"))) {
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

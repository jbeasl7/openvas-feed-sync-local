# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122583");
  script_cve_id("CVE-2006-0903", "CVE-2006-4031", "CVE-2006-4227", "CVE-2006-7232", "CVE-2007-1420", "CVE-2007-2583", "CVE-2007-2691", "CVE-2007-2692", "CVE-2007-3781", "CVE-2007-3782");
  script_tag(name:"creation_date", value:"2015-10-08 11:48:37 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2008-0364)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2008-0364");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2008-0364.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql' package(s) announced via the ELSA-2008-0364 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[5.0.45-7]
- Adjust thread stack requests to allow for platform-specific guard page size,
 necessary to prevent stack overrun on PPC with RHEL5's 64K page size.
Resolves: #435391
- Remove calendar-dependent queries from 'view' test, necessary to get
 regression tests to pass after 2007.

[5.0.45-6]
- Back-port upstream fixes for CVE-2007-5925, CVE-2007-5969, CVE-2007-6303.
Resolves: #422211

[5.0.45-1]
- Update to MySQL 5.0.45
Resolves: #256501, #240813, #246309, #254012
Resolves: #280811, #316451, #349121, #367131
- Synchronize with current Fedora package, which is pretty well tested by now,
 see past bzs 245770, 241912, 233771, 221085, 223713, 203910, 193559, 199368

[5.0.22-3]
- Fix CVE-2007-3780: remote DOS via bad password length byte
Resolves: #257681");

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

  if(!isnull(res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.0.45~7.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~5.0.45~7.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-devel", rpm:"mysql-devel~5.0.45~7.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-server", rpm:"mysql-server~5.0.45~7.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-test", rpm:"mysql-test~5.0.45~7.el5", rls:"OracleLinux5"))) {
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

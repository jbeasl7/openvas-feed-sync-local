# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122351");
  script_cve_id("CVE-2010-0540", "CVE-2010-0542", "CVE-2010-1748");
  script_tag(name:"creation_date", value:"2015-10-06 11:17:20 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2010-0490)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux3|OracleLinux4|OracleLinux5)");

  script_xref(name:"Advisory-ID", value:"ELSA-2010-0490");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2010-0490.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups' package(s) announced via the ELSA-2010-0490 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1:1.3.7-18:.4]
- Don't set domain= for cookies.

[1:1.3.7-18:.3]
- Save classes.conf when a class member printer is
 deleted (bug #594621, STR #3505).

[1:1.3.7-18:.2]
- Applied patch for CVE-2010-1748 (web interface memory disclosure,
 STR #3577, bug #591983).
- Applied patch for CVE-2010-0542 (texttops unchecked memory
 allocation failure leading to NULL pointer dereference, STR #3516,
 bug #587746).
- Applied patch for CVE-2010-0540 (CUPS administrator web interface
 CSRF, STR #3498, bug #588805).

[1:1.3.7-18:.1]
- Update classes when a printer is removed (bug #581902).");

  script_tag(name:"affected", value:"'cups' package(s) on Oracle Linux 3, Oracle Linux 4, Oracle Linux 5.");

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

if(release == "OracleLinux3") {

  if(!isnull(res = isrpmvuln(pkg:"cups", rpm:"cups~1.1.17~13.3.65", rls:"OracleLinux3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~1.1.17~13.3.65", rls:"OracleLinux3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.1.17~13.3.65", rls:"OracleLinux3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux4") {

  if(!isnull(res = isrpmvuln(pkg:"cups", rpm:"cups~1.1.22~0.rc1.9.32.el4_8.6", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~1.1.22~0.rc1.9.32.el4_8.6", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.1.22~0.rc1.9.32.el4_8.6", rls:"OracleLinux4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"cups", rpm:"cups~1.3.7~18.el5_5.4", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~1.3.7~18.el5_5.4", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.3.7~18.el5_5.4", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-lpd", rpm:"cups-lpd~1.3.7~18.el5_5.4", rls:"OracleLinux5"))) {
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

# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123813");
  script_cve_id("CVE-2012-2145");
  script_tag(name:"creation_date", value:"2015-10-06 11:08:54 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2012-1269)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-1269");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-1269.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-qpid, qpid-cpp, qpid-qmf, qpid-tools' package(s) announced via the ELSA-2012-1269 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"python-qpid
[0.14-11]
- BZs: 825078
- Resolves: rhbz#840053

qpid-cpp
[0.14-22.0.1.el6_3 ]
- Update summary and description in specfile to be product neutral

[0.14-22]
- BZs: 609685, 849654, 854004

[0.14-21]
- BZs: 831365, 840982, 844618

[0.14-20]
- BZs: 683711, 689408, 825078, 834608, 841196, 841488

[0.14-19]
- BZs: 609685, 683711, 693444, 707682, 729311, 801465, 808090,
 809357, 811481, 817283, 826989, 831365, 835628

[0.14-18]
- BZs: 609685, 729311, 808090, 809357, 817283

qpid-qmf
[0.14-14.0.1.el6_3]
- Change build vendor

[0.14-14]
- BZs: 693845, 773700, 806869, 847331

qpid-tools
[0.14-6]
- Resolves: rhbz#840058
- Fixed: Bug 850111 - qpid-stat -c mech column data missing");

  script_tag(name:"affected", value:"'python-qpid, qpid-cpp, qpid-qmf, qpid-tools' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-qpid", rpm:"python-qpid~0.14~11.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-qpid-qmf", rpm:"python-qpid-qmf~0.14~14.0.1.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qpid-cpp", rpm:"qpid-cpp~0.14~22.0.1.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qpid-cpp-client", rpm:"qpid-cpp-client~0.14~22.0.1.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qpid-cpp-client-ssl", rpm:"qpid-cpp-client-ssl~0.14~22.0.1.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qpid-cpp-server", rpm:"qpid-cpp-server~0.14~22.0.1.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qpid-cpp-server-ssl", rpm:"qpid-cpp-server-ssl~0.14~22.0.1.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qpid-qmf", rpm:"qpid-qmf~0.14~14.0.1.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qpid-tools", rpm:"qpid-tools~0.14~6.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-qpid-qmf", rpm:"ruby-qpid-qmf~0.14~14.0.1.el6_3", rls:"OracleLinux6"))) {
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

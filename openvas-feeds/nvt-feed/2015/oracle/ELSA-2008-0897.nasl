# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122548");
  script_cve_id("CVE-2008-1145", "CVE-2008-3443", "CVE-2008-3655", "CVE-2008-3656", "CVE-2008-3657", "CVE-2008-3790", "CVE-2008-3905");
  script_tag(name:"creation_date", value:"2015-10-08 11:47:46 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2008-0897)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux4|OracleLinux5)");

  script_xref(name:"Advisory-ID", value:"ELSA-2008-0897");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2008-0897.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby' package(s) announced via the ELSA-2008-0897 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.8.5-5.el5_2.5]
- Build with -fno-strict-aliasing.

[1.8.5-5.el5_2.4]
- security fixes. (#461590)
- CVE-2008-3655: multiple insufficient safe mode restrictions.
- CVE-2008-3656: WEBrick DoS vulnerability (CPU consumption).
- CVE-2008-3657: missing taintness checks in dl module.
- CVE-2008-3905: use of predictable source port and transaction id in DNS
 requests done by resolv.rb module.
- CVE-2008-3443: Memory allocation failure in Ruby regex engine
 (remotely exploitable DoS).
- CVE-2008-3790: DoS vulnerability in the REXML module.");

  script_tag(name:"affected", value:"'ruby' package(s) on Oracle Linux 4, Oracle Linux 5.");

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

if(release == "OracleLinux4") {

  if(!isnull(res = isrpmvuln(pkg:"irb", rpm:"irb~1.8.1~7.0.1.el4_7.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby", rpm:"ruby~1.8.1~7.0.1.el4_7.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~1.8.1~7.0.1.el4_7.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-docs", rpm:"ruby-docs~1.8.1~7.0.1.el4_7.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-libs", rpm:"ruby-libs~1.8.1~7.0.1.el4_7.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-mode", rpm:"ruby-mode~1.8.1~7.0.1.el4_7.1", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-tcltk", rpm:"ruby-tcltk~1.8.1~7.0.1.el4_7.1", rls:"OracleLinux4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"ruby", rpm:"ruby~1.8.5~5.el5_2.5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~1.8.5~5.el5_2.5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-docs", rpm:"ruby-docs~1.8.5~5.el5_2.5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~1.8.5~5.el5_2.5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-libs", rpm:"ruby-libs~1.8.5~5.el5_2.5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-mode", rpm:"ruby-mode~1.8.5~5.el5_2.5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-rdoc", rpm:"ruby-rdoc~1.8.5~5.el5_2.5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-ri", rpm:"ruby-ri~1.8.5~5.el5_2.5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-tcltk", rpm:"ruby-tcltk~1.8.5~5.el5_2.5", rls:"OracleLinux5"))) {
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

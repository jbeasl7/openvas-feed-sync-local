# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123811");
  script_cve_id("CVE-2012-2313", "CVE-2012-2390", "CVE-2012-3430");
  script_tag(name:"creation_date", value:"2015-10-06 11:08:52 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2012-2035)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-2035");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-2035.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-uek, mlnx_en-2.6.32-300.32.3.el5uek, mlnx_en-2.6.32-300.32.3.el6uek, ofa-2.6.32-300.32.3.el5uek, ofa-2.6.32-300.32.3.el6uek' package(s) announced via the ELSA-2012-2035 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-300.32.3]
- dl2k: Clean up rio_ioctl (Stephan Mueller) [Orabug: 14675306] {CVE-2012-2313}
- hugetlb: fix resv_map leak in error path (Christoph Lameter) [Orabug: 14676403] {CVE-2012-2390}
- rds: set correct msg_namelen (Jay Fenlason) [Orabug: 14676504] {CVE-2012-3430}");

  script_tag(name:"affected", value:"'kernel-uek, mlnx_en-2.6.32-300.32.3.el5uek, mlnx_en-2.6.32-300.32.3.el6uek, ofa-2.6.32-300.32.3.el5uek, ofa-2.6.32-300.32.3.el6uek' package(s) on Oracle Linux 5, Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~300.32.3.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~300.32.3.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~300.32.3.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~300.32.3.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~300.32.3.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~300.32.3.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~300.32.3.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlnx_en-2.6.32-300.32.3.el5uek", rpm:"mlnx_en-2.6.32-300.32.3.el5uek~1.5.7~2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlnx_en-2.6.32-300.32.3.el5uekdebug", rpm:"mlnx_en-2.6.32-300.32.3.el5uekdebug~1.5.7~2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-300.32.3.el5uek", rpm:"ofa-2.6.32-300.32.3.el5uek~1.5.1~4.0.58", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-300.32.3.el5uekdebug", rpm:"ofa-2.6.32-300.32.3.el5uekdebug~1.5.1~4.0.58", rls:"OracleLinux5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~300.32.3.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~300.32.3.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~300.32.3.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~300.32.3.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~300.32.3.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~300.32.3.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~300.32.3.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlnx_en-2.6.32-300.32.3.el6uek", rpm:"mlnx_en-2.6.32-300.32.3.el6uek~1.5.7~0.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlnx_en-2.6.32-300.32.3.el6uekdebug", rpm:"mlnx_en-2.6.32-300.32.3.el6uekdebug~1.5.7~0.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-300.32.3.el6uek", rpm:"ofa-2.6.32-300.32.3.el6uek~1.5.1~4.0.58", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-300.32.3.el6uekdebug", rpm:"ofa-2.6.32-300.32.3.el6uekdebug~1.5.1~4.0.58", rls:"OracleLinux6"))) {
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

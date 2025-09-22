# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122306");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2010-3067", "CVE-2010-3477", "CVE-2010-3904");
  script_tag(name:"creation_date", value:"2015-10-06 11:16:23 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-22T05:38:11+0000");
  script_tag(name:"last_modification", value:"2025-01-22 05:38:11 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-27 19:23:03 +0000 (Thu, 27 Jun 2024)");

  script_name("Oracle: Security Advisory (ELSA-2010-2009)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2010-2009");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2010-2009.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the '' package(s) announced via the ELSA-2010-2009 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Following security bugs are fixed in this errata

CVE-2010-3904
When copying data to userspace, the RDS protocol failed to verify that the user-provided address was a valid
userspace address. A local unprivileged user could issue specially crafted socket calls to write arbitrary
values into kernel memory and potentially escalate privileges to root.

CVE-2010-3067
Integer overflow in the do_io_submit function in fs/aio.c in the Linux kernel before 2.6.36-rc4-next-20100915 allows
local users to cause a denial of service or possibly have unspecified other impact via crafted use of the io_submit
system call.

CVE-2010-3477
The tcf_act_police_dump function in net/sched/act_police.c in the actions implementation in the network queueing
functionality in the Linux kernel before 2.6.36-rc4 does not properly initialize certain structure members, which
allows local users to obtain potentially sensitive information from kernel memory via vectors involving a dump
operation. NOTE: this vulnerability exists because of an incomplete fix for CVE-2010-2942.

kernel:

[2.6.32-100.21.1.el5]
- [rds] fix access issue with rds (Chris Mason) {CVE-2010-3904}
- [fuse] linux-2.6.32-fuse-return-EGAIN-if-not-connected-bug-10154489.patch
- [net] linux-2.6.32-net-sched-fix-kernel-leak-in-act_police.patch
- [aio] linux-2.6.32-aio-check-for-multiplication-overflow-in-do_io_subm.patch

ofa:

[1.5.1-4.0.23]
- Fix rds permissions checks during copies

[1.5.1-4.0.21]
- Update to BXOFED 1.5.1-1.3.6-5");

  script_tag(name:"affected", value:"'' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~100.21.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~100.21.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~100.21.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~100.21.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~100.21.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~100.21.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~100.21.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-100.21.1.el5", rpm:"ofa-2.6.32-100.21.1.el5~1.5.1~4.0.23", rls:"OracleLinux5"))) {
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

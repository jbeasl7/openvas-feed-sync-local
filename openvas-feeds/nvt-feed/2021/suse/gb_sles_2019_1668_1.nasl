# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1668.1");
  script_cve_id("CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11487", "CVE-2019-3846");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-04 19:53:50 +0000 (Tue, 04 Jun 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1668-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1668-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191668-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137597");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-June/005618.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel (Live Patch 32 for SLE 12 SP1)' package(s) announced via the SUSE-SU-2019:1668-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 3.12.74-60_64_107 fixes several issues.

The following security issues were fixed:

- CVE-2019-3846: A flaw that allowed an attacker to corrupt memory and possibly escalate privileges was found in the mwifiex kernel module while connecting to a malicious wireless network (bsc#1136446).
- CVE-2019-11477: A sequence of SACKs may have been crafted by a remote attacker such that one can trigger an integer overflow, leading to a kernel panic. (bsc#1137586).
- CVE-2019-11478: It was possible to send a crafted sequence of SACKs which would fragment the TCP retransmission queue. A remote attacker may have been able to further exploit the fragmented queue to cause an expensive linked-list walk for subsequent SACKs received for that same TCP connection. (bsc#1137586)
- CVE-2019-11487: The Linux kernel allowed page->_refcount reference count overflow, with resultant use-after-free issues, if about 140 GiB of RAM exists. This is related to fs/fuse/dev.c, fs/pipe.c, fs/splice.c, include/linux/mm.h, include/linux/pipe_fs_i.h, kernel/trace/trace.c, mm/gup.c, and mm/hugetlb.c. It can occur with FUSE requests (bsc#1133191).");

  script_tag(name:"affected", value:"'Linux Kernel (Live Patch 32 for SLE 12 SP1)' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_61-52_136-default", rpm:"kgraft-patch-3_12_61-52_136-default~11~2.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_61-52_136-xen", rpm:"kgraft-patch-3_12_61-52_136-xen~11~2.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_61-52_141-default", rpm:"kgraft-patch-3_12_61-52_141-default~9~2.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_61-52_141-xen", rpm:"kgraft-patch-3_12_61-52_141-xen~9~2.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_61-52_146-default", rpm:"kgraft-patch-3_12_61-52_146-default~7~2.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_61-52_146-xen", rpm:"kgraft-patch-3_12_61-52_146-xen~7~2.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_61-52_149-default", rpm:"kgraft-patch-3_12_61-52_149-default~3~2.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_61-52_149-xen", rpm:"kgraft-patch-3_12_61-52_149-xen~3~2.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_104-default", rpm:"kgraft-patch-3_12_74-60_64_104-default~7~2.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_104-xen", rpm:"kgraft-patch-3_12_74-60_64_104-xen~7~2.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_107-default", rpm:"kgraft-patch-3_12_74-60_64_107-default~7~2.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_107-xen", rpm:"kgraft-patch-3_12_74-60_64_107-xen~7~2.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_110-default", rpm:"kgraft-patch-3_12_74-60_64_110-default~3~2.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_110-xen", rpm:"kgraft-patch-3_12_74-60_64_110-xen~3~2.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_96-default", rpm:"kgraft-patch-3_12_74-60_64_96-default~11~2.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_96-xen", rpm:"kgraft-patch-3_12_74-60_64_96-xen~11~2.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_99-default", rpm:"kgraft-patch-3_12_74-60_64_99-default~9~2.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_99-xen", rpm:"kgraft-patch-3_12_74-60_64_99-xen~9~2.1", rls:"SLES12.0SP1"))) {
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

# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.0772.1");
  script_cve_id("CVE-2013-6382", "CVE-2013-7263", "CVE-2013-7264", "CVE-2013-7265", "CVE-2014-1737", "CVE-2014-1738");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:20 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:0772-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:0772-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20140772-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2014:0772-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise Server 10 Service Pack 4 LTSS kernel has been updated to fix various security issues and several bugs.

The following security issues have been addressed:

 *

 CVE-2013-6382: Multiple buffer underflows in the XFS implementation in the Linux kernel through 3.12.1 allow local users to cause a denial of service (memory corruption) or possibly have unspecified
 other impact by leveraging the CAP_SYS_ADMIN capability for a (1)
XFS_IOC_ATTRLIST_BY_HANDLE or (2) XFS_IOC_ATTRLIST_BY_HANDLE_32 ioctl call with a crafted length value, related to the xfs_attrlist_by_handle function in fs/xfs/xfs_ioctl.c and the xfs_compat_attrlist_by_handle function in fs/xfs/xfs_ioctl32.c. (bnc#852553)

 *

 CVE-2013-7263: The Linux kernel before 3.12.4 updates certain length values before ensuring that associated data structures have been initialized, which allows local users to obtain sensitive information from kernel stack memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system call, related to net/ipv4/ping.c, net/ipv4/raw.c, net/ipv4/udp.c,
net/ipv6/raw.c, and net/ipv6/udp.c. (bnc#857643)

 *

 CVE-2013-7264: The l2tp_ip_recvmsg function in net/l2tp/l2tp_ip.c in the Linux kernel before 3.12.4 updates a certain length value before ensuring that an associated data structure has been initialized, which allows local users to obtain sensitive information from kernel stack memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system call.
(bnc#857643)

 *

 CVE-2013-7265: The pn_recvmsg function in net/phonet/datagram.c in the Linux kernel before 3.12.4 updates a certain length value before ensuring that an associated data structure has been initialized, which allows local users to obtain sensitive information from kernel stack memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system call.
(bnc#857643)

 *

 CVE-2014-1737: The raw_cmd_copyin function in drivers/block/floppy.c in the Linux kernel through 3.14.3 does not properly handle error conditions during processing of an FDRAWCMD ioctl call, which allows local users to trigger kfree operations and gain privileges by leveraging write access to a /dev/fd device. (bnc#875798)

 *

 CVE-2014-1738: The raw_cmd_copyout function in drivers/block/floppy.c in the Linux kernel through 3.14.3 does not properly restrict access to certain pointers during processing of an FDRAWCMD ioctl call, which allows local users to obtain sensitive information from kernel heap memory by leveraging write access to a
/dev/fd device. (bnc#875798)

Additionally, the following non-security bugs have been fixed:

 * tcp: syncookies: reduce cookie lifetime to 128 seconds (bnc#833968).
 * tcp: syncookies: reduce mss table to four values (bnc#833968).
 * ia64: Change default PSR.ac from '1' to '0' (Fix erratum #237)
 (bnc#874108).
 * tty: fix up atime/mtime mess, take three (bnc#797175).

Security Issues references:

 * CVE-2013-6382
 * ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 10-SP4.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.16.60~0.107.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.16.60~0.107.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.16.60~0.107.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kdump", rpm:"kernel-kdump~2.6.16.60~0.107.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kdumppae", rpm:"kernel-kdumppae~2.6.16.60~0.107.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.16.60~0.107.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.16.60~0.107.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.16.60~0.107.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vmi", rpm:"kernel-vmi~2.6.16.60~0.107.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vmipae", rpm:"kernel-vmipae~2.6.16.60~0.107.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.16.60~0.107.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.16.60~0.107.1", rls:"SLES10.0SP4"))) {
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

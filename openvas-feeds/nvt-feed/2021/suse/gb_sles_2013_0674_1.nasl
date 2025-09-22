# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.0674.1");
  script_cve_id("CVE-2012-4530", "CVE-2013-0160", "CVE-2013-0216", "CVE-2013-0231", "CVE-2013-0268", "CVE-2013-0871");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:25 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:0674-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:0674-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20130674-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux kernel' package(s) announced via the SUSE-SU-2013:0674-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This Linux kernel update fixes various security issues and bugs in the SUSE Linux Enterprise 10 SP4 kernel.

The following security issues have been fixed:

 *

 CVE-2013-0871: A race condition in ptrace(2) could be used by local attackers to crash the kernel and/or execute code in kernel context.

 *

 CVE-2013-0160: Avoid side channel information leaks from the ptys via ptmx, which allowed local attackers to guess keypresses.

 *

 CVE-2012-4530: Avoid leaving bprm->interp on the stack which might have leaked information from the kernel to userland attackers.

 *

 CVE-2013-0268: The msr_open function in arch/x86/kernel/msr.c in the Linux kernel allowed local users to bypass intended capability restrictions by executing a crafted application as root, as demonstrated by msr32.c.

 *

 CVE-2013-0216: The Xen netback functionality in the Linux kernel allowed guest OS users to cause a denial of service (loop) by triggering ring pointer corruption.

 *

 CVE-2013-0231: The pciback_enable_msi function in the PCI backend driver
(drivers/xen/pciback/conf_space_capability_msi.c) in Xen for the Linux kernel allowed guest OS users with PCI device access to cause a denial of service via a large number of kernel log messages. NOTE: some of these details are obtained from third party information.

Also the following non-security bugs have been fixed:

S/390:

 * s390x: tty struct used after free (bnc#809692,
LTC#90216).
 * s390x/kernel: sched_clock() overflow (bnc#799611,
LTC#87978).
 * qeth: set new mac even if old mac is gone
(bnc#789012,LTC#86643).
 * qeth: set new mac even if old mac is gone (2)
(bnc#792697,LTC#87138).
 * qeth: fix deadlock between recovery and bonding driver (bnc#785101,LTC#85905).
 * dasd: check count address during online setting
(bnc#781485,LTC#85346).
 * hugetlbfs: add missing TLB invalidation
(bnc#781485,LTC#85463).
 * s390/kernel: make user-access pagetable walk code huge page aware (bnc#781485,LTC#85455).

XEN:

 * xen/netback: fix netbk_count_requests().
 * xen: properly bound buffer access when parsing cpu/availability.
 * xen/scsiback/usbback: move cond_resched() invocations to proper place.
 * xen/pciback: properly clean up after calling pcistub_device_find().
 * xen: add further backward-compatibility configure options.
 * xen/PCI: suppress bogus warning on old hypervisors.
 * xenbus: fix overflow check in xenbus_dev_write().
 * xen/x86: do not corrupt %eip when returning from a signal handler.

Other:

 * kernel: Restrict clearing TIF_SIGPENDING (bnc#742111).
 * kernel: recalc_sigpending_tsk fixes (bnc#742111).
 * xfs: Do not reclaim new inodes in xfs_sync_inodes()
(bnc#770980).
 * jbd: Avoid BUG_ON when checkpoint stalls (bnc#795335).
 * reiserfs: Fix int overflow while calculating free space (bnc#795075).
 * cifs: clarify the meaning of tcpStatus == CifsGood
(bnc#769093).
 * cifs: do not allow cifs_reconnect to exit with NULL socket pointer ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux kernel' package(s) on SUSE Linux Enterprise Desktop 10-SP4, SUSE Linux Enterprise Server 10-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.16.60~0.101.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.16.60~0.101.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.16.60~0.101.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-iseries64", rpm:"kernel-iseries64~2.6.16.60~0.101.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kdump", rpm:"kernel-kdump~2.6.16.60~0.101.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kdumppae", rpm:"kernel-kdumppae~2.6.16.60~0.101.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~2.6.16.60~0.101.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.16.60~0.101.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.16.60~0.101.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.16.60~0.101.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vmi", rpm:"kernel-vmi~2.6.16.60~0.101.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vmipae", rpm:"kernel-vmipae~2.6.16.60~0.101.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.16.60~0.101.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.16.60~0.101.1", rls:"SLES10.0SP4"))) {
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

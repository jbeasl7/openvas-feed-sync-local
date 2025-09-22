# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0150.1");
  script_cve_id("CVE-2013-2547", "CVE-2018-12232", "CVE-2018-14625", "CVE-2018-16862", "CVE-2018-16884", "CVE-2018-18281", "CVE-2018-18397", "CVE-2018-19407", "CVE-2018-19824", "CVE-2018-19854", "CVE-2018-19985", "CVE-2018-20169", "CVE-2018-9568");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:31 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-30 17:21:29 +0000 (Wed, 30 Jan 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0150-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0150-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190150-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:0150-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 kernel for Azure was updated to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2018-9568: In sk_clone_lock of sock.c, there is a possible memory
 corruption due to type confusion. This could lead to local escalation of
 privilege with no additional execution privileges needed. User
 interaction is not needed for exploitation. (bnc#1118319).

CVE-2018-12232: In net/socket.c there is a race condition between
 fchownat and close in cases where they target the same socket file
 descriptor, related to the sock_close and sockfs_setattr functions.
 fchownat did not increment the file descriptor reference count, which
 allowed close to set the socket to NULL during fchownat's execution,
 leading to a NULL pointer dereference and system crash (bnc#1097593).

CVE-2018-14625: A flaw was found where an attacker may be able to have
 an uncontrolled read to kernel-memory from within a vm guest. A race
 condition between connect() and close() function may allow an attacker
 using the AF_VSOCK protocol to gather a 4 byte information leak or
 possibly intercept or corrupt AF_VSOCK messages destined to other
 clients (bnc#1106615).

CVE-2018-16862: A security flaw was found in the way that the cleancache
 subsystem clears an inode after the final file truncation (removal). The
 new file created with the same inode may contain leftover pages from
 cleancache and the old file data instead of the new one (bnc#1117186).

CVE-2018-16884: NFS41+ shares mounted in different network namespaces at
 the same time can make bc_svc_process() use wrong back-channel IDs and
 cause a use-after-free vulnerability. Thus a malicious container user
 can cause a host kernel memory corruption and a system panic. Due to the
 nature of the flaw, privilege escalation cannot be fully ruled out
 (bnc#1119946).

CVE-2018-18281: The mremap() syscall performs TLB flushes after dropping
 pagetable locks. If a syscall such as ftruncate() removes entries from
 the pagetables of a task that is in the middle of mremap(), a stale TLB
 entry can remain for a short time that permits access to a physical page
 after it has been released back to the page allocator and reused.
 (bnc#1113769).

CVE-2018-18397: The userfaultfd implementation mishandled access control
 for certain UFFDIO_ ioctl calls, as demonstrated by allowing local users
 to write data into holes in a tmpfs file (if the user has read-only
 access to that file, and that file contains holes), related to
 fs/userfaultfd.c and mm/userfaultfd.c (bnc#1117656).

CVE-2018-19407: The vcpu_scan_ioapic function in arch/x86/kvm/x86.c
 allowed local users to cause a denial of service (NULL pointer
 dereference and BUG) via crafted system calls that reach a situation
 where ioapic is uninitialized (bnc#1116841).

CVE-2018-19824: A local user could exploit a use-after-free in the ALSA
 driver by supplying a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~5.19.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~5.19.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~5.19.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~5.19.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~5.19.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~5.19.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~5.19.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~5.19.1", rls:"SLES15.0"))) {
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

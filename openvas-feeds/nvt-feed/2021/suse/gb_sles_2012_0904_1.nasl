# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.0904.1");
  script_cve_id("CVE-2012-2123", "CVE-2012-2136", "CVE-2012-2319", "CVE-2012-2383", "CVE-2012-2384", "CVE-2012-2390", "CVE-2012-2663", "CVE-2012-3375", "CVE-2012-3400");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:27 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:0904-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:0904-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20120904-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux kernel' package(s) announced via the SUSE-SU-2012:0904-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP1 kernel have been updated to fix various bugs and security issues.

The following security issues have been fixed:

 *

 CVE-2012-3400: Several buffer overread and overwrite errors in the UDF logical volume descriptor code were fixed that might have allowed local attackers able to mount UDF volumes to crash the kernel or potentially gain privileges.

 *

 CVE-2012-3375: A local denial of service in the last epoll fix was fixed.

 *

 CVE-2012-2384: A integer overflow in i915_gem_do_execbuffer() was fixed that might be used by local attackers to crash the kernel or potentially execute code.

 *

 CVE-2012-2383: A integer overflow in i915_gem_execbuffer2() was fixed that might be used by local attackers to crash the kernel or potentially execute code.

 *

 CVE-2012-2390: Memiory leaks in the hugetlbfs map reservation code were fixed that could be used by local attackers to exhaust machine memory.

 *

 CVE-2012-2123: The filesystem cabability handling was not fully correct, allowing local users to bypass fscaps related restrictions to disable e.g. address space randomization.

 *

 CVE-2012-2136: Validation of data_len before allocating fragments of skbs was fixed that might have allowed a heap overflow.

 *

 CVE-2012-2319: Fixed potential buffer overflows in the hfsplus filesystem, which might be exploited by local attackers able to mount such filesystems.

Several leapsecond related bug fixes have been created:

 * hrtimer: provide clock_was_set_delayed() (bnc#768632).
 * time: Fix leapsecond triggered hrtimer/futex load spike issue (bnc#768632).
 * ntp: fix leap second hrtimer deadlock (bnc#768632).
 * ntp: avoid printk under xtime_lock (bnc#767684).

The following non-security issues have been fixed:

 * tcp: drop SYN+FIN messages to avoid memory leaks
(bnc#765102)
 * be2net: Fix EEH error reset before a flash dump completes (bnc#755546).
 * REVERT svcrpc: destroy server sockets all at once
(bnc#769210).
 * sched: Make sure to not re-read variables after validation (bnc#769685).
 * audit: Do not send uninitialized data for AUDIT_TTY_GET (bnc#755513).
 * dlm: do not depend on sctp (bnc#729247, bnc#763656).
 * RPC: killing RPC tasks races fixed (bnc#765548).
 * vlan/core: Fix memory leak/corruption on VLAN GRO_DROP (bnc#758058).
 * CPU hotplug, cpusets, suspend/resume: Do not modify cpusets during suspend/resume (bnc#752858).
 * ioat2: kill pending flag (bnc#765022).
 * Fix massive driver induced spin_lock_bh() contention.
 * ipmi: Fix IPMI errors due to timing problems
(bnc#761988).
 * xen: fix VM_FOREIGN users after c/s 878:eba6fe6d8d53
(bnc#760974).
 * xen: gntdev: fix multi-page slot allocation
(bnc#760974).
 * rpm/kernel-binary.spec.in: Own the right -kdump initrd (bnc#764500)
 * kernel: pfault task state race (bnc#764098,LTC#81724).
 * xfrm: take net hdr len into account for esp payload size calculation (bnc#759545).
 * bonding: do ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux kernel' package(s) on SUSE Linux Enterprise Desktop 11-SP1, SUSE Linux Enterprise High Availability Extension 11-SP1, SUSE Linux Enterprise Server 11-SP1.");

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

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"btrfs-kmp-default", rpm:"btrfs-kmp-default~0_2.6.32.59_0.7~0.3.107", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"btrfs-kmp-pae", rpm:"btrfs-kmp-pae~0_2.6.32.59_0.7~0.3.107", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"btrfs-kmp-xen", rpm:"btrfs-kmp-xen~0_2.6.32.59_0.7~0.3.107", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ext4dev-kmp-default", rpm:"ext4dev-kmp-default~0_2.6.32.59_0.7~7.9.74", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ext4dev-kmp-pae", rpm:"ext4dev-kmp-pae~0_2.6.32.59_0.7~7.9.74", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ext4dev-kmp-ppc64", rpm:"ext4dev-kmp-ppc64~0_2.6.32.59_0.7~7.9.74", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ext4dev-kmp-trace", rpm:"ext4dev-kmp-trace~0_2.6.32.59_0.7~7.9.74", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ext4dev-kmp-xen", rpm:"ext4dev-kmp-xen~0_2.6.32.59_0.7~7.9.74", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hyper-v-kmp-default", rpm:"hyper-v-kmp-default~0_2.6.32.59_0.7~0.18.20", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hyper-v-kmp-pae", rpm:"hyper-v-kmp-pae~0_2.6.32.59_0.7~0.18.20", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hyper-v-kmp-trace", rpm:"hyper-v-kmp-trace~0_2.6.32.59_0.7~0.18.20", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.32.59~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~2.6.32.59~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~2.6.32.59~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~2.6.32.59~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~2.6.32.59~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~2.6.32.59~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~2.6.32.59~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.32.59~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~2.6.32.59~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~2.6.32.59~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~2.6.32.59~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~2.6.32.59~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~2.6.32.59~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.32.59~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.32.59~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~2.6.32.59~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~2.6.32.59~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~2.6.32.59~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.32.59~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~2.6.32.59~0.7.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.32.59~0.7.1", rls:"SLES11.0SP1"))) {
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

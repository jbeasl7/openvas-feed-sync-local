# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.0554.1");
  script_cve_id("CVE-2011-1083", "CVE-2011-2494", "CVE-2011-4086", "CVE-2011-4127", "CVE-2011-4131", "CVE-2011-4132", "CVE-2012-1090", "CVE-2012-1097", "CVE-2012-1146", "CVE-2012-1179");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:28 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2012-05-17 17:30:00 +0000 (Thu, 17 May 2012)");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:0554-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:0554-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20120554-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux kernel' package(s) announced via the SUSE-SU-2012:0554-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP2 kernel has been updated to 3.0.26, which fixes a lot of bugs and security issues.

The following security issues have been fixed:

 * CVE-2012-1179: A locking problem in transparent hugepage support could be used by local attackers to potentially crash the host, or via kvm a privileged guest user could crash the kvm host system.
 * CVE-2011-4127: A potential hypervisor escape by issuing SG_IO commands to partitiondevices was fixed by restricting access to these commands.
 * CVE-2012-1146: A local attacker could oops the kernel using memory control groups and eventfds.
 * CVE-2011-1083: Limit the path length users can build using epoll() to avoid local attackers consuming lots of kernel CPU time.
 * CVE-2012-1097: The regset common infrastructure assumed that regsets would always have .get and .set methods, but necessarily .active methods. Unfortunately people have since written regsets without .set method, so NULL pointer dereference attacks were possible.
 * CVE-2011-2494: Access to the /proc/pid/taskstats file requires root access to avoid side channel (timing keypresses etc.) attacks on other users.
 * CVE-2011-4086: Fixed a oops in jbd/jbd2 that could be caused by specific filesystem access patterns.
 * CVE-2011-4131: A malicious NFSv4 server could have caused a oops in the nfsv4 acl handling.
 * CVE-2011-4132: Fixed a oops in jbd/jbd2 that could be caused by mounting a malicious prepared filesystem.

(Also included are all fixes from the 3.0.14 -> 3.0.25 stable kernel updates.)

The following non-security issues have been fixed:

EFI:

 * efivars: add missing parameter to efi_pstore_read().

BTRFS:

 * add a few error cleanups.
 * btrfs: handle errors when excluding super extents
(FATE#306586 bnc#751015).
 * btrfs: Fix missing goto in btrfs_ioctl_clone.
 * btrfs: Fixed mishandled -EAGAIN error case from btrfs_split_item (bnc#750459).
 * btrfs: disallow unequal data/metadata blocksize for mixed block groups (FATE#306586).
 * btrfs: enhance superblock sanity checks (FATE#306586 bnc#749651).
 * btrfs: update message levels (FATE#306586).
 * btrfs 3.3-rc6 updates: o avoid setting ->d_op twice
(FATE#306586 bnc#731387). o btrfs: fix wrong information of the directory in the snapshot (FATE#306586). o btrfs: fix race in reada (FATE#306586). o btrfs: do not add both copies of DUP to reada extent tree (FATE#306586). o btrfs:
stop silently switching single chunks to raid0 on balance
(FATE#306586). o btrfs: fix locking issues in find_parent_nodes() (FATE#306586). o btrfs: fix casting error in scrub reada code (FATE#306586).
 * btrfs sync with upstream up to 3.3-rc5 (FATE#306586)
 * btrfs: Sector Size check during Mount
 * btrfs: avoid positive number with ERR_PTR
 * btrfs: return the internal error unchanged if btrfs_get_extent_fiemap() call failed for SEEK_DATA/SEEK_HOLE inquiry.
 * btrfs: fix trim 0 bytes after a device delete
 * btrfs: do not ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux kernel' package(s) on SUSE Linux Enterprise Desktop 11-SP2, SUSE Linux Enterprise High Availability Extension 11-SP2, SUSE Linux Enterprise Server 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.26~0.7.6", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.26~0.7.6", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.26~0.7.6", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.26~0.7.6", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.26~0.7.6", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.26~0.7.6", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.26~0.7.6", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.26~0.7.6", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.26~0.7.6", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.26~0.7.6", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.26~0.7.6", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.26~0.7.6", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.26~0.7.6", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.26~0.7.6", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.26~0.7.6", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.26~0.7.6", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.26~0.7.6", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.26~0.7.6", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.26~0.7.6", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.26~0.7.6", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.26~0.7.6", rls:"SLES11.0SP2"))) {
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

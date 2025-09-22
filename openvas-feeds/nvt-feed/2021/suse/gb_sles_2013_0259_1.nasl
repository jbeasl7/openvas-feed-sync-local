# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.0259.1");
  script_cve_id("CVE-2012-0957", "CVE-2012-4530", "CVE-2012-4565");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:25 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:0259-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:0259-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20130259-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel update for SLE11 SP2' package(s) announced via the SUSE-SU-2013:0259-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP2 kernel was updated to 3.0.58, fixing various bugs and security issues.

It contains the following feature enhancement:
- Enable various md/raid10 and DASD enhancements.
 (FATE#311379) These make is possible for RAID10 to cope
 with DASD devices being slow for various reasons - the
 affected device will be temporarily removed from the
 array.

Also added support for reshaping of RAID10 arrays.

mdadm changes will be published to support this feature.

The following security issues were fixed:
- CVE-2012-4565: A division by zero in the TCP Illinois
 algorithm was fixed.

- CVE-2012-0957: The UNAME26 personality leaked kernel
 memory information.

- CVE-2012-4530: Kernel stack content was disclosed via
 binfmt_script load_script().

Following non security issues were fixed: BTRFS:
- btrfs: reset path lock state to zero.
- btrfs: fix off-by-one in lseek.
- btrfs: fix btrfs_cont_expand() freeing IS_ERR em.
- btrfs: update timestamps on truncate().
- btrfs: put csums on the right ordered extent.
- btrfs: use existing align macros in btrfs_allocate()
- btrfs: fix off-by-one error of the reserved size of
 btrfs_allocate()
- btrfs: add fiemaps flag check
- btrfs: fix permissions of empty files not affected by
 umask
- btrfs: do not auto defrag a file when doing directIO
- btrfs: fix wrong return value of btrfs_truncate_page()
- btrfs: Notify udev when removing device
- btrfs: fix permissions of empty files not affected by
 umask
- btrfs: fix hash overflow handling
- btrfs: do not delete a subvolume which is in a R/O
 subvolume
- btrfs: remove call to btrfs_wait_ordered_extents to avoid
 potential deadlock.
- btrfs: update the checks for mixed block groups with big
 metadata blocks
- btrfs: Fix use-after-free in __btrfs_end_transaction
- btrfs: use commit root when loading free space cache.
- btrfs: avoid setting ->d_op twice (FATE#306586
 bnc#731387).
- btrfs: fix race in reada (FATE#306586).
- btrfs: do not add both copies of DUP to reada extent tree
- btrfs: do not mount when we have a sectorsize unequal to
 PAGE_SIZE
- btrfs: add missing unlocks to transaction abort paths
- btrfs: avoid sleeping in verify_parent_transid while
 atomic
- btrfs: disallow unequal data/metadata blocksize for mixed
 block groups
- btrfs: enhance superblock sanity checks (bnc#749651).
- btrfs: sanitizing ->fs_info, parts 1-5.
- btrfs: make open_ctree() return int.
- btrfs: kill pointless reassignment of ->s_fs_info in
 btrfs_fill_super().
- btrfs: merge free_fs_info() calls on fill_super failures.
- btrfs: make free_fs_info() call ->kill_sb() unconditional.
- btrfs: consolidate failure exits in btrfs_mount() a bit.
- btrfs: let ->s_fs_info point to fs_info, not root...
- btrfs: take allocation of ->tree_root into open_ctree().


DASD:
- Update DASD blk_timeout patches after review from IBM
 (FATE#311379):
* dasd: Abort all requests from ioctl
* dasd: Disable block ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel update for SLE11 SP2' package(s) on SUSE Linux Enterprise Desktop 11-SP2, SUSE Linux Enterprise High Availability Extension 11-SP2, SUSE Linux Enterprise Server 11-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.58~0.6.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.58~0.6.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.58~0.6.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.58~0.6.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.58~0.6.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.58~0.6.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.58~0.6.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.58~0.6.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.58~0.6.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.58~0.6.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.58~0.6.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.58~0.6.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.58~0.6.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.58~0.6.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.58~0.6.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.58~0.6.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.58~0.6.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.58~0.6.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.58~0.6.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.58~0.6.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.58~0.6.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.1.3_06_3.0.58_0.6.2~0.7.16", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-trace", rpm:"xen-kmp-trace~4.1.3_06_3.0.58_0.6.2~0.7.16", rls:"SLES11.0SP2"))) {
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

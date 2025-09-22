# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.0689.1");
  script_cve_id("CVE-2012-2127", "CVE-2012-2133", "CVE-2012-2313", "CVE-2012-2319");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:27 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:0689-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:0689-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20120689-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel update for SLE11 SP2' package(s) announced via the SUSE-SU-2012:0689-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP2 kernel was updated to 3.0.31, fixing lots of bugs and security issues.

Various security and bug fixes contained in the Linux 3.0 stable releases 3.0.27 up to 3.0.31 are included, but not explicitly listed below.

Following security issues were fixed: CVE-2012-2313: The dl2k network card driver lacked permission handling for some ethtool ioctls, which could allow local attackers to start/stop the network card.

CVE-2012-2133: A use after free bug in hugetlb support could be used by local attackers to crash the system.

CVE-2012-2127: Various leaks in namespace handling over fork where fixed, which could be exploited by e.g. vsftpd access by remote users.

CVE-2012-2319: A memory corruption when mounting a hfsplus filesystem was fixed that could be used by local attackers able to mount filesystem to crash the system.

Following non security bugs were fixed by this update:
BTRFS:
- btrfs: partial revert of truncation improvements
 (bnc#748463 bnc#760279).
- btrfs: fix eof while discarding extents
- btrfs: check return value of bio_alloc() properly
- btrfs: return void from clear_state_bit
- btrfs: avoid possible use-after-free in clear_extent_bit()
- btrfs: Make free_ipath() deal gracefully with NULL
 pointers
- btrfs: do not call free_extent_buffer twice in
 iterate_irefs
- btrfs: add missing read locks in backref.c
- btrfs: fix max chunk size check in chunk allocator
- btrfs: double unlock bug in error handling
- btrfs: do not return EINTR
- btrfs: fix btrfs_ioctl_dev_info() crash on missing device
- btrfs: fix that check_int_data mount option was ignored
- btrfs: do not mount when we have a sectorsize unequal to
 PAGE_SIZE
- btrfs: avoid possible use-after-free in clear_extent_bit()
- btrfs: retrurn void from clear_state_bit
- btrfs: Fix typo in free-space-cache.c
- btrfs: remove the ideal caching code
- btrfs: remove search_start and search_end from
 find_free_extent and callers
- btrfs: adjust the write_lock_level as we unlock
- btrfs: actually call btrfs_init_lockdep
- btrfs: fix regression in scrub path resolving
- btrfs: show useful info in space reservation tracepoint
- btrfs: flush out and clean up any block device pages
 during mount
- btrfs: fix deadlock during allocating chunks
- btrfs: fix race between direct io and autodefrag
- btrfs: fix the mismatch of page->mapping
- btrfs: fix recursive defragment with autodefrag option
- btrfs: add a check to decide if we should defrag the range
- btrfs: do not bother to defrag an extent if it is a big
 real extent
- btrfs: update to the right index of defragment
- btrfs: Fix use-after-free in __btrfs_end_transaction
- btrfs: stop silently switching single chunks to raid0 on
 balance
- btrfs: add wrappers for working with alloc profiles
- btrfs: make profile_is_valid() check more strict
- btrfs: move alloc_profile_is_valid() to volumes.c
- btrfs: add get_restripe_target() helper
- btrfs: ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.31~0.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.31~0.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.31~0.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.31~0.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.31~0.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.31~0.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.31~0.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.31~0.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.31~0.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.31~0.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.31~0.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.31~0.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.31~0.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.31~0.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.31~0.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.31~0.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.31~0.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.31~0.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.31~0.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.31~0.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.31~0.9.1", rls:"SLES11.0SP2"))) {
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

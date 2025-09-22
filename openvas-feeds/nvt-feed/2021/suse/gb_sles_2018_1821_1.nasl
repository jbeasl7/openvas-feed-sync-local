# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1821.1");
  script_cve_id("CVE-2018-3665");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:43 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-11 20:19:13 +0000 (Wed, 11 Jul 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1821-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1821-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181821-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068054");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1079152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088997");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088998");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088999");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089005");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089011");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089203");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089204");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089207");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089209");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089210");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089215");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089218");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089219");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089222");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089225");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089228");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089230");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089233");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089234");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089236");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089238");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089239");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1093194");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1093195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1093196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1093197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1093198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094421");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094425");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1095241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097443");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097445");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989401");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-June/004221.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:1821-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security and bugfixes.

This new feature was added:

- Btrfs: Remove empty block groups in the background

The following security bugs were fixed:

- CVE-2018-3665: Prevent disclosure of FPU registers (including XMM and AVX
 registers) between processes. These registers might contain encryption keys
 when doing SSE accelerated AES enc/decryption (bsc#1087086)

The following non-security bugs were fixed:

- ALSA: timer: Fix pause event notification (bsc#973378).
- Btrfs: Avoid trucating page or punching hole in a already existed hole (bsc#1088998).
- Btrfs: Avoid truncate tailing page if fallocate range does not exceed inode size (bsc#1094424).
- Btrfs: Fix lost-data-profile caused by auto removing bg.
- Btrfs: Fix misuse of chunk mutex
- Btrfs: Fix out-of-space bug (bsc#1089231).
- Btrfs: Set relative data on clear btrfs_block_group_cache->pinned.
- Btrfs: Use ref_cnt for set_block_group_ro() (bsc#1089239).
- Btrfs: add alloc_fs_devices and switch to it (bsc#1089205).
- Btrfs: add btrfs_alloc_device and switch to it (bsc#1089204).
- Btrfs: add missing discards when unpinning extents with -o discard.
- Btrfs: add missing inode update when punching hole (bsc#1089006).
- Btrfs: add support for asserts (bsc#1089207).
- Btrfs: avoid syncing log in the fast fsync path when not necessary (bsc#1089010).
- Btrfs: btrfs_issue_discard ensure offset/length are aligned to sector boundaries.
- Btrfs: check pending chunks when shrinking fs to avoid corruption (bsc#1089235).
- Btrfs: cleanup backref search commit root flag stuff (bsc#1089200).
- Btrfs: delete chunk allocation attemp when setting block group ro.
- Btrfs: do not leak transaction in btrfs_sync_file() (bsc#1089210).
- Btrfs: do not mix the ordered extents of all files together during logging the inodes (bsc#1089214).
- Btrfs: do not remove extents and xattrs when logging new names (bsc#1089005).
- Btrfs: eliminate races in worker stopping code (bsc#1089211).
- Btrfs: ensure deletion from pinned_chunks list is protected.
- Btrfs: explictly delete unused block groups in close_ctree and ro-remount.
- Btrfs: fix -ENOSPC on block group removal.
- Btrfs: fix -ENOSPC when finishing block group creation.
- Btrfs: fix BUG_ON in btrfs_orphan_add() when delete unused block group.
- Btrfs: fix NULL pointer crash when running balance and scrub concurrently (bsc#1089220).
- Btrfs: fix chunk allocation regression leading to transaction abort (bsc#1089236).
- Btrfs: fix crash caused by block group removal.
- Btrfs: fix data loss in the fast fsync path (bsc#1089007).
- Btrfs: fix deadlock caused by fsync when logging directory entries (bsc#1093194).
- Btrfs: fix directory inconsistency after fsync log replay (bsc#1089001).
- Btrfs: fix directory recovery from fsync log (bsc#1088999).
- Btrfs: fix empty symlink after creating symlink and fsync parent dir (bsc#1093195).
- ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~108.57.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~108.57.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~108.57.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~108.57.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~108.57.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem", rpm:"kernel-bigmem~3.0.101~108.57.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-base", rpm:"kernel-bigmem-base~3.0.101~108.57.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-devel", rpm:"kernel-bigmem-devel~3.0.101~108.57.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~108.57.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~108.57.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~108.57.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~108.57.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~108.57.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~108.57.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~108.57.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~108.57.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~108.57.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~108.57.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~108.57.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~108.57.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~108.57.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~108.57.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~108.57.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~108.57.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~108.57.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~108.57.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~108.57.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~108.57.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~108.57.1", rls:"SLES11.0SP4"))) {
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

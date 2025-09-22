# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.0739.1");
  script_cve_id("CVE-2021-3348");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-16 18:01:10 +0000 (Tue, 16 Feb 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:0739-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:0739-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20210739-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078720");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1081134");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181574");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181996");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181998");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182047");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182173");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182175");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182243");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182248");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182302");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182310");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182438");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182447");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182448");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182449");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182460");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182465");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182560");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182561");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182571");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182590");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182652");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-March/008449.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:0739-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel Azure was updated to receive various security and bugfixes.

The following security bugs was fixed:

- CVE-2021-3348: Fixed a use-after-free read in nbd_queue_rq (bsc#1181504).

The following non-security bugs were fixed:

- ACPI: configfs: add missing check after configfs_register_default_group() (git-fixes).
- ACPI: property: Fix fwnode string properties matching (git-fixes).
- ACPI: property: Satisfy kernel doc validator (part 1) (git-fixes).
- ALSA: usb-audio: Fix PCM buffer allocation in non-vmalloc mode (git-fixes).
- arm64: Update config file. Set CONFIG_WATCHDOG_SYSFS to true (bsc#1182560)
- ASoC: cs42l56: fix up error handling in probe (git-fixes).
- ath9k: fix data bus crash when setting nf_override via debugfs (git-fixes).
- block: fix use-after-free in disk_part_iter_next (bsc#1182610).
- Bluetooth: btqcomsmd: Fix a resource leak in error handling paths in the probe function (git-fixes).
- Bluetooth: drop HCI device reference before return (git-fixes).
- Bluetooth: Fix initializing response id after clearing struct (git-fixes).
- Bluetooth: Put HCI device if inquiry procedure interrupts (git-fixes).
- bonding: Fix reference count leak in bond_sysfs_slave_add (git-fixes).
- bonding: wait for sysfs kobject destruction before freeing struct slave (git-fixes).
- btrfs: Cleanup try_flush_qgroup (bsc#1182047).
- btrfs: correctly calculate item size used when item key collision happens (bsc#1181996).
- btrfs: correctly validate compression type (bsc#1182269).
- btrfs: delete the ordered isize update code (bsc#1181998).
- btrfs: Do not flush from btrfs_delayed_inode_reserve_metadata (bsc#1182047).
- btrfs: do not set path->leave_spinning for truncate (bsc#1181998).
- btrfs: factor out extent dropping code from hole punch handler (bsc#1182038).
- btrfs: fix cloning range with a hole when using the NO_HOLES feature (bsc#1182038).
- btrfs: fix data bytes_may_use underflow with fallocate due to failed quota reserve (bsc#1182130)
- btrfs: fix ENOSPC errors, leading to transaction aborts, when cloning extents (bsc#1182038).
- btrfs: fix hole extent items with a zero size after range cloning (bsc#1182038).
- btrfs: fix lost i_size update after cloning inline extent (bsc#1181998).
- btrfs: fix mount failure caused by race with umount (bsc#1182248).
- btrfs: Fix race between extent freeing/allocation when using bitmaps (bsc#1181574).
- btrfs: fix unexpected cow in run_delalloc_nocow (bsc#1181987).
- btrfs: fix unexpected failure of nocow buffered writes after snapshotting when low on space (bsc#1181987).
- btrfs: Free correct amount of space in btrfs_delayed_inode_reserve_metadata (bsc#1182047).
- btrfs: incremental send, fix file corruption when no-holes feature is enabled (bsc#1182184).
- btrfs: Introduce extent_io_tree::owner to distinguish different io_trees (bsc#1181998).
- btrfs: introduce per-inode file extent tree ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.47.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.47.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.47.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.47.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.47.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.47.1", rls:"SLES12.0SP5"))) {
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

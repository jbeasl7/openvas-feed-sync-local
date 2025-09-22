# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3003.1");
  script_cve_id("CVE-2018-14613", "CVE-2018-14617", "CVE-2018-16276", "CVE-2018-16597", "CVE-2018-17182", "CVE-2018-7480", "CVE-2018-7757");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:36 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-17 10:31:32 +0000 (Sat, 17 Mar 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3003-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3003-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183003-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087209");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091815");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1095344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1095753");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102715");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102875");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103156");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106434");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106594");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107924");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108096");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110297");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110337");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:3003-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP3 kernel was updated to 4.4.156 to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2018-16597: Incorrect access checking in overlayfs mounts could have been
 used by local attackers to modify or truncate files in the underlying
 filesystem (bnc#1106512).
- CVE-2018-14613: Prevent invalid pointer dereference in io_ctl_map_page() when
 mounting and operating a crafted btrfs image, caused by a lack of block group
 item validation in check_leaf_item (bsc#1102896)
- CVE-2018-14617: Prevent NULL pointer dereference and panic in
 hfsplus_lookup() when opening a file (that is purportedly a hard link) in an
 hfs+ filesystem that has malformed catalog data, and is mounted read-only
 without a metadata directory (bsc#1102870)
- CVE-2018-16276: Incorrect bounds checking in the yurex USB driver in
 yurex_read allowed local attackers to use user access read/writes to crash the
 kernel or potentially escalate privileges (bsc#1106095)
- CVE-2018-7757: Memory leak in the sas_smp_get_phy_events function in
 drivers/scsi/libsas/sas_expander.c allowed local users to cause a denial of
 service (memory consumption) via many read accesses to files in the
 /sys/class/sas_phy directory, as demonstrated by the
 /sys/class/sas_phy/phy-1:0:12/invalid_dword_count file (bnc#1084536)
- CVE-2018-7480: The blkcg_init_queue function allowed local users to cause a
 denial of service (double free) or possibly have unspecified other impact by
 triggering a creation failure (bsc#1082863).
- CVE-2018-17182: The vmacache_flush_all function in mm/vmacache.c
 mishandled sequence number overflows. An attacker can trigger a
 use-after-free (and possibly gain privileges) via certain thread creation,
 map, unmap, invalidation, and dereference operations (bnc#1108399).

The following non-security bugs were fixed:

- asm/sections: add helpers to check for section data (bsc#1063026).
- ASoC: wm8994: Fix missing break in switch (bnc#1012382).
- block: bvec_nr_vecs() returns value for wrong slab (bsc#1082979).
- bpf: fix overflow in prog accounting (bsc#1012382).
- btrfs: Add checker for EXTENT_CSUM (bsc#1102882, bsc#1102896, bsc#1102879, bsc#1102877, bsc#1102875,).
- btrfs: Add sanity check for EXTENT_DATA when reading out leaf (bsc#1102882, bsc#1102896, bsc#1102879, bsc#1102877, bsc#1102875,).
- btrfs: Check if item pointer overlaps with the item itself (bsc#1102882, bsc#1102896, bsc#1102879, bsc#1102877, bsc#1102875,).
- btrfs: Check that each block group has corresponding chunk at mount time (bsc#1102882, bsc#1102896, bsc#1102879, bsc#1102877, bsc#1102875,).
- btrfs: Introduce mount time chunk <-> dev extent mapping check (bsc#1102882, bsc#1102896, bsc#1102879, bsc#1102877, bsc#1102875,).
- btrfs: Move leaf and node validation checker to tree-checker.c (bsc#1102882, bsc#1102896, bsc#1102879, bsc#1102877, bsc#1102875,).
- btrfs: relocation: Only ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.156~94.57.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.156~94.57.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.156~94.57.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.156~94.57.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.156~94.57.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.156~94.57.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.156~94.57.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.156~94.57.1", rls:"SLES12.0SP3"))) {
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

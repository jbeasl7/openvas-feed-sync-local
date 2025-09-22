# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0801.1");
  script_cve_id("CVE-2019-2024", "CVE-2019-9213");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-21 14:34:07 +0000 (Fri, 21 Jun 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0801-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0801-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190801-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090435");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109137");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109248");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119019");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120691");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121713");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125315");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126389");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127561");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128166");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128565");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128696");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128756");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129238");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129239");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129415");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129417");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129923");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-March/005261.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:0801-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP3 kernel was updated to 4.4.176 to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2019-9213: expand_downwards in mm/mmap.c lacked a check for the mmap minimum address, which made it easier for attackers to exploit kernel NULL pointer dereferences on non-SMAP platforms. This is related to a capability check for the wrong task (bnc#1128166).
- CVE-2019-2024: A use-after-free when disconnecting a source was fixed which could lead to crashes. bnc#1129179).

The following non-security bugs were fixed:

- ax25: fix possible use-after-free (bnc#1012382).
- block_dev: fix crash on chained bios with O_DIRECT (bsc#1090435).
- block: do not use bio->bi_vcnt to figure out segment number (bsc#1128893).
- bnxt_re: Fix couple of memory leaks that could lead to IOMMU call traces (bsc#1020413).
- bpf: fix replace_map_fd_with_map_ptr's ldimm64 second imm field (bsc#1012382).
- btrfs: ensure that a DUP or RAID1 block group has exactly two stripes (bsc#1128452).
- ceph: avoid repeatedly adding inode to mdsc->snap_flush_list (bsc#1126773).
- ch: add missing mutex_lock()/mutex_unlock() in ch_release() (bsc#1124235).
- ch: fixup refcounting imbalance for SCSI devices (bsc#1124235).
- copy_mount_string: Limit string length to PATH_MAX (bsc#1082943).
- device property: Fix the length used in PROPERTY_ENTRY_STRING() (bsc#1129770).
- drivers: hv: vmbus: Check for ring when getting debug info (bsc#1126389).
- drm: Fix error handling in drm_legacy_addctx (bsc#1106929)
- drm/nouveau/bios/ramcfg: fix missing parentheses when calculating RON (bsc#1106929)
- drm/nouveau/pmu: do not print reply values if exec is false (bsc#1106929)
- drm/radeon/evergreen_cs: fix missing break in switch statement (bsc#1106929)
- drm/vmwgfx: Do not double-free the mode stored in par->set_mode (bsc#1103429)
- enic: add wq clean up budget (bsc#1075697, bsc#1120691. bsc#1102959).
- enic: do not overwrite error code (bnc#1012382).
- fbdev: chipsfb: remove set but not used variable 'size' (bsc#1106929)
- ibmvnic: Report actual backing device speed and duplex values (bsc#1129923).
- ibmvscsi: Fix empty event pool access during host removal (bsc#1119019).
- input: mms114 - fix license module information (bsc#1087092).
- iommu/dmar: Fix buffer overflow during PCI bus notification (bsc#1129237).
- iommu/io-pgtable-arm-v7s: Only kmemleak_ignore L2 tables (bsc#1129238).
- iommu/vt-d: Check identity map for hot-added devices (bsc#1129239).
- iommu/vt-d: Fix NULL pointer reference in intel_svm_bind_mm() (bsc#1129240).
- ixgbe: fix crash in build_skb Rx code path (git-fixes).
- kabi: protect struct inet_peer (kabi).
- kallsyms: Handle too long symbols in kallsyms.c (bsc#1126805).
- KMPs: obsolete older KMPs of the same flavour (bsc#1127155, bsc#1109137).
- kvm: arm/arm64: vgic-its: Check CBASER/BASER validity before enabling the ITS (bsc#1109248).
- kvm: arm/arm64: ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.176~94.88.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.176~94.88.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.176~94.88.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.176~94.88.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.176~94.88.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.176~94.88.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.176~94.88.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.176~94.88.1", rls:"SLES12.0SP3"))) {
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

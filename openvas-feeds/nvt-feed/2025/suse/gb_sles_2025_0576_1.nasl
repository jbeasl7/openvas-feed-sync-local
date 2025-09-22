# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0576.1");
  script_cve_id("CVE-2024-50199", "CVE-2024-53095", "CVE-2024-53104", "CVE-2024-53144", "CVE-2024-53166", "CVE-2024-53177", "CVE-2024-54680", "CVE-2024-56600", "CVE-2024-56601", "CVE-2024-56602", "CVE-2024-56623", "CVE-2024-56631", "CVE-2024-56642", "CVE-2024-56645", "CVE-2024-56648", "CVE-2024-56650", "CVE-2024-56658", "CVE-2024-56661", "CVE-2024-56664", "CVE-2024-56704", "CVE-2024-56759", "CVE-2024-57791", "CVE-2024-57792", "CVE-2024-57798", "CVE-2024-57849", "CVE-2024-57893", "CVE-2024-57897", "CVE-2024-8805");
  script_tag(name:"creation_date", value:"2025-02-19 11:58:11 +0000 (Wed, 19 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-20 18:05:47 +0000 (Fri, 20 Dec 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0576-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0576-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250576-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234690");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234884");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235134");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235230");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235249");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235430");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235451");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235521");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235759");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235814");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236628");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-February/020371.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:0576-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2024-50199: mm/swapfile: skip HugeTLB pages for unuse_vma (bsc#1233112).
- CVE-2024-53104: media: uvcvideo: Skip parsing frames of type UVC_VS_UNDEFINED in uvc_parse_format (bsc#1234025).
- CVE-2024-53166: block, bfq: fix bfqq uaf in bfq_limit_depth() (bsc#1234884).
- CVE-2024-53177: smb: prevent use-after-free due to open_cached_dir error paths (bsc#1234896).
- CVE-2024-56600: net: inet6: do not leave a dangling sk pointer in inet6_create() (bsc#1235217).
- CVE-2024-56601: net: inet: do not leave a dangling sk pointer in inet_create() (bsc#1235230).
- CVE-2024-56602: net: ieee802154: do not leave a dangling sk pointer in ieee802154_create() (bsc#1235521).
- CVE-2024-56623: scsi: qla2xxx: Fix use after free on unload (bsc#1235466).
- CVE-2024-56631: scsi: sg: Fix slab-use-after-free read in sg_release() (bsc#1235480).
- CVE-2024-56642: tipc: Fix use-after-free of kernel socket in cleanup_bearer() (bsc#1235433).
- CVE-2024-56645: can: j1939: j1939_session_new(): fix skb reference counting (bsc#1235134).
- CVE-2024-56648: net: hsr: avoid potential out-of-bound access in fill_frame_info() (bsc#1235451).
- CVE-2024-56650: netfilter: x_tables: fix LED ID check in led_tg_check() (bsc#1235430).
- CVE-2024-56658: net: defer final 'struct net' free in netns dismantle (bsc#1235441).
- CVE-2024-56664: bpf, sockmap: Fix race between element replace and close() (bsc#1235249).
- CVE-2024-56704: 9p/xen: fix release of IRQ (bsc#1235584).
- CVE-2024-56759: btrfs: fix use-after-free when COWing tree bock and tracing is enabled (bsc#1235645).
- CVE-2024-57791: net/smc: check return value of sock_recvmsg when draining clc data (bsc#1235759).
- CVE-2024-57792: power: supply: gpio-charger: Fix set charge current limits (bsc#1235764).
- CVE-2024-57798: drm/dp_mst: Ensure mst_primary pointer is valid in drm_dp_mst_handle_up_req() (bsc#1235818).
- CVE-2024-57849: s390/cpum_sf: Handle CPU hotplug remove during sampling (bsc#1235814).
- CVE-2024-57893: ALSA: seq: oss: Fix races at processing SysEx messages (bsc#1235920).
- CVE-2024-57897: drm/amdkfd: Correct the migration DMA map direction (bsc#1235969).

The following non-security bugs were fixed:

- NFS: Adjust the amount of readahead performed by NFS readdir (bsc#1231847).
- NFS: Do not flush the readdir cache in nfs_dentry_iput() (bsc#1231847).
- NFS: Improve heuristic for readdirplus (bsc#1231847).
- NFS: Trigger the 'ls -l' readdir heuristic sooner (bsc#1231847).
- tipc: fix NULL deref in cleanup_bearer() (bsc#1235433).
- x86/static-call: Remove early_boot_irqs_disabled check to fix Xen PVH dom0 (git-fixes).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150400.24.150.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150400.24.150.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150400.24.150.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150400.24.150.1.150400.24.74.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150400.24.150.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150400.24.150.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150400.24.150.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150400.24.150.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150400.24.150.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150400.24.150.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150400.24.150.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150400.24.150.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150400.24.150.1", rls:"SLES15.0SP4"))) {
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

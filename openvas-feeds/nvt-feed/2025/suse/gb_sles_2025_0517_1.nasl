# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0517.1");
  script_cve_id("CVE-2023-4244", "CVE-2023-52923", "CVE-2024-35863", "CVE-2024-50199", "CVE-2024-53104", "CVE-2024-56600", "CVE-2024-56601", "CVE-2024-56623", "CVE-2024-56650", "CVE-2024-56658", "CVE-2024-56664", "CVE-2024-56759", "CVE-2024-57791", "CVE-2024-57798", "CVE-2024-57849", "CVE-2024-57893");
  script_tag(name:"creation_date", value:"2025-02-14 12:27:30 +0000 (Fri, 14 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-03 14:53:23 +0000 (Mon, 03 Feb 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0517-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0517-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250517-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215420");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235230");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235249");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235430");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235759");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235814");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236104");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-February/020337.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:0517-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2024-35863: Fixed potential UAF in is_valid_oplock_break() (bsc#1224763).
- CVE-2024-50199: mm/swapfile: skip HugeTLB pages for unuse_vma (bsc#1233112).
- CVE-2024-53104: media: uvcvideo: Skip parsing frames of type UVC_VS_UNDEFINED in uvc_parse_format (bsc#1234025).
- CVE-2024-56600: net: inet6: do not leave a dangling sk pointer in inet6_create() (bsc#1235217).
- CVE-2024-56601: net: inet: do not leave a dangling sk pointer in inet_create() (bsc#1235230).
- CVE-2024-56623: scsi: qla2xxx: Fix use after free on unload (bsc#1235466).
- CVE-2024-56650: netfilter: x_tables: fix LED ID check in led_tg_check() (bsc#1235430).
- CVE-2024-56658: net: defer final 'struct net' free in netns dismantle (bsc#1235441).
- CVE-2024-56664: bpf, sockmap: Fix race between element replace and close() (bsc#1235249).
- CVE-2024-56759: btrfs: fix use-after-free when COWing tree bock and tracing is enabled (bsc#1235645).
- CVE-2024-57791: net/smc: check return value of sock_recvmsg when draining clc data (bsc#1235759).
- CVE-2024-57798: drm/dp_mst: Ensure mst_primary pointer is valid in drm_dp_mst_handle_up_req() (bsc#1235818).
- CVE-2024-57849: s390/cpum_sf: Handle CPU hotplug remove during sampling (bsc#1235814).
- CVE-2024-57893: ALSA: seq: oss: Fix races at processing SysEx messages (bsc#1235920).

The following non-security bugs were fixed:

- NFS: Adjust the amount of readahead performed by NFS readdir (bsc#1231847).
- NFS: Do not flush the readdir cache in nfs_dentry_iput() (bsc#1231847).
- NFS: Improve heuristic for readdirplus (bsc#1231847).
- NFS: Reduce readdir stack usage (bsc#1231847).
- NFS: Trigger the 'ls -l' readdir heuristic sooner (bsc#1231847).
- NFS: Use kmemdup_nul() in nfs_readdir_make_qstr() (bsc#1231847).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.3.18~150300.59.191.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.3.18~150300.59.191.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150300.59.191.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150300.59.191.1.150300.18.113.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150300.59.191.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150300.59.191.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150300.59.191.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150300.59.191.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150300.59.191.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150300.59.191.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150300.59.191.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150300.59.191.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150300.59.191.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.3.18~150300.59.191.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150300.59.191.1", rls:"SLES15.0SP3"))) {
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

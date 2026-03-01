# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0471.1");
  script_cve_id("CVE-2023-53714", "CVE-2024-42103", "CVE-2024-53070", "CVE-2024-53149", "CVE-2025-22047", "CVE-2025-37813", "CVE-2025-38243", "CVE-2025-38322", "CVE-2025-38379", "CVE-2025-38539", "CVE-2025-39689", "CVE-2025-39813", "CVE-2025-39829", "CVE-2025-39913", "CVE-2025-40097", "CVE-2025-40202", "CVE-2025-40257", "CVE-2025-40259", "CVE-2025-68284", "CVE-2025-68285", "CVE-2025-68775", "CVE-2025-68804", "CVE-2025-68808", "CVE-2025-68813", "CVE-2025-68819", "CVE-2025-71078", "CVE-2025-71081", "CVE-2025-71083", "CVE-2025-71085", "CVE-2025-71089", "CVE-2025-71111", "CVE-2025-71112", "CVE-2025-71120", "CVE-2025-71136", "CVE-2025-71147", "CVE-2026-22999", "CVE-2026-23001", "CVE-2026-23010");
  script_tag(name:"creation_date", value:"2026-02-16 04:44:21 +0000 (Mon, 16 Feb 2026)");
  script_version("2026-02-27T05:55:46+0000");
  script_tag(name:"last_modification", value:"2026-02-27 05:55:46 +0000 (Fri, 27 Feb 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-26 18:42:40 +0000 (Thu, 26 Feb 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0471-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0471-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260471-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228490");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233563");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246447");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247030");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252900");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253451");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254447");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254465");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256528");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256665");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256682");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256759");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257236");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257473");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257603");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024142.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2026:0471-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP6 kernel was updated to fix various security issues

The following security issues were fixed:

- CVE-2025-40257: mptcp: fix a race in mptcp_pm_del_add_timer() (bsc#1254842).
- CVE-2025-40259: scsi: sg: Do not sleep in atomic context (bsc#1254845).
- CVE-2025-68284: libceph: prevent potential out-of-bounds writes in handle_auth_session_key() (bsc#1255377).
- CVE-2025-68285: libceph: fix potential use-after-free in have_mon_and_osd_map() (bsc#1255401).
- CVE-2025-68775: net/handshake: duplicate handshake cancellations leak socket (bsc#1256665).
- CVE-2025-68813: ipvs: fix ipv4 null-ptr-deref in route error path (bsc#1256641).
- CVE-2025-71085: ipv6: BUG() in pskb_expand_head() as part of calipso_skbuff_setattr() (bsc#1256623).
- CVE-2025-71089: iommu: disable SVA when CONFIG_X86 is set (bsc#1256612).
- CVE-2025-71112: net: hns3: add VLAN id validation before using (bsc#1256726).
- CVE-2025-71120: SUNRPC: svcauth_gss: avoid NULL deref on zero length gss_token in gss_read_proxy_verf (bsc#1256779).
- CVE-2026-22999: net/sched: sch_qfq: do not free existing class in qfq_change_class() (bsc#1257236).
- CVE-2026-23001: macvlan: fix possible UAF in macvlan_forward_source() (bsc#1257232).
- CVE-2026-23010: ipv6: Fix use-after-free in inet6_addr_del() (bsc#1257332).

The following non security issues were fixed:

- bpf/selftests: test_select_reuseport_kern: Remove unused header (bsc#1257603).
- btrfs: do not strictly require dirty metadata threshold for metadata writepages (stable-fixes).
- cifs: Fix copy offload to flush destination region (bsc#1252511).
- cifs: Fix flushing, invalidation and file size with copy_file_range() (bsc#1252511).
- cifs: add new field to track the last access time of cfid (git-fixes).
- ext4: use optimized mballoc scanning regardless of inode format (bsc#1254378).
- ice: use netif_get_num_default_rss_queues() (bsc#1247712).
- mm, page_alloc, thp: prevent reclaim for __GFP_THISNODE THP allocations (bsc#1253087).
- net: hv_netvsc: reject RSS hash key programming without RX indirection table (bsc#1257473).
- net: tcp: allow zero-window ACK update the window (bsc#1254767).
- sched: Increase sched_tick_remote timeout (bsc#1254510).
- scsi: storvsc: Process unsupported MODE_SENSE_10 (bsc#1257296).
- smb: change return type of cached_dir_lease_break() to bool (git-fixes).
- smb: client: ensure open_cached_dir_by_dentry() only returns valid cfid (git-fixes).
- smb: client: remove unused fid_lock (git-fixes).
- smb: client: short-circuit in open_cached_dir_by_dentry() if !dentry (git-fixes).
- smb: client: split cached_fid bitfields to avoid shared-byte RMW races (bsc#1250748).
- smb: client: update cfid->last_access_time in open_cached_dir_by_dentry() (git-fixes).
- smb: improve directory cache reuse for readdir operations (bsc#1252712).
- x86: make page fault handling disable interrupts properly (git-fixes).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~6.4.0~150600.23.87.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~6.4.0~150600.23.87.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~6.4.0~150600.23.87.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~6.4.0~150600.23.87.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~6.4.0~150600.23.87.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~6.4.0~150600.23.87.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~6.4.0~150600.23.87.1.150600.12.40.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~6.4.0~150600.23.87.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~6.4.0~150600.23.87.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~6.4.0~150600.23.87.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~6.4.0~150600.23.87.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~6.4.0~150600.23.87.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~6.4.0~150600.23.87.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~6.4.0~150600.23.87.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~6.4.0~150600.23.87.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~6.4.0~150600.23.87.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~6.4.0~150600.23.87.1", rls:"SLES15.0SP6"))) {
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

# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0474.1");
  script_cve_id("CVE-2022-49604", "CVE-2022-49943", "CVE-2022-49980", "CVE-2022-50232", "CVE-2022-50697", "CVE-2023-52433", "CVE-2023-52874", "CVE-2023-52923", "CVE-2023-53178", "CVE-2023-53407", "CVE-2023-53412", "CVE-2023-53417", "CVE-2023-53418", "CVE-2023-53714", "CVE-2023-54142", "CVE-2023-54243", "CVE-2024-26581", "CVE-2024-26661", "CVE-2024-26832", "CVE-2024-50143", "CVE-2024-54031", "CVE-2025-21658", "CVE-2025-21760", "CVE-2025-21764", "CVE-2025-21765", "CVE-2025-21766", "CVE-2025-38068", "CVE-2025-38129", "CVE-2025-38159", "CVE-2025-38375", "CVE-2025-38563", "CVE-2025-38565", "CVE-2025-38684", "CVE-2025-40044", "CVE-2025-40139", "CVE-2025-40257", "CVE-2025-40300", "CVE-2025-68183", "CVE-2025-68284", "CVE-2025-68285", "CVE-2025-68312", "CVE-2025-68771", "CVE-2025-68813", "CVE-2025-71085", "CVE-2025-71089", "CVE-2025-71112", "CVE-2025-71116", "CVE-2025-71120", "CVE-2026-22999", "CVE-2026-23001");
  script_tag(name:"creation_date", value:"2026-02-16 04:44:21 +0000 (Mon, 16 Feb 2026)");
  script_version("2026-02-27T05:55:46+0000");
  script_tag(name:"last_modification", value:"2026-02-27 05:55:46 +0000 (Fri, 27 Feb 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-26 18:42:40 +0000 (Thu, 26 Feb 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0474-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0474-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260474-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220137");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220144");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236104");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238754");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245210");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245751");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247177");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247483");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248306");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249156");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253028");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253409");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254447");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254465");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255594");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256582");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257236");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257473");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024140.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2026:0474-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 kernel was updated to fix various security issues

The following security issues were fixed:

- CVE-2022-50697: mrp: introduce active flags to prevent UAF when applicant uninit (bsc#1255594).
- CVE-2023-54142: gtp: Fix use-after-free in __gtp_encap_destroy() (bsc#1256095).
- CVE-2023-54243: netfilter: ebtables: fix table blob use-after-free (bsc#1255908).
- CVE-2025-38068: crypto: lzo - Fix compression buffer overrun (bsc#1245210).
- CVE-2025-38129: page_pool: fix inconsistency for page_pool_ring_lock() (bsc#1245723).
- CVE-2025-38159: wifi: rtw88: fix the 'para' buffer size to avoid reading out of bounds (bsc#1245751).
- CVE-2025-38375: virtio-net: ensure the received length does not exceed allocated size (bsc#1247177).
- CVE-2025-40257: mptcp: fix a race in mptcp_pm_del_add_timer() (bsc#1254842).
- CVE-2025-40300: Documentation/hw-vuln: Add VMSCAPE documentation (bsc#1247483).
- CVE-2025-68183: ima: don't clear IMA_DIGSIG flag when setting or removing non-IMA xattr (bsc#1255251).
- CVE-2025-68284: libceph: prevent potential out-of-bounds writes in handle_auth_session_key() (bsc#1255377).
- CVE-2025-68285: libceph: fix potential use-after-free in have_mon_and_osd_map() (bsc#1255401).
- CVE-2025-68312: usbnet: Prevents free active kevent (bsc#1255171).
- CVE-2025-68771: ocfs2: fix kernel BUG in ocfs2_find_victim_chain (bsc#1256582).
- CVE-2025-68813: ipvs: fix ipv4 null-ptr-deref in route error path (bsc#1256641).
- CVE-2025-71085: ipv6: BUG() in pskb_expand_head() as part of calipso_skbuff_setattr() (bsc#1256623).
- CVE-2025-71089: iommu: disable SVA when CONFIG_X86 is set (bsc#1256612).
- CVE-2025-71112: net: hns3: add VLAN id validation before using (bsc#1256726).
- CVE-2025-71116: libceph: make decode_pool() more resilient against corrupted osdmaps (bsc#1256744).
- CVE-2025-71120: SUNRPC: svcauth_gss: avoid NULL deref on zero length gss_token in gss_read_proxy_verf (bsc#1256779).
- CVE-2026-22999: net/sched: sch_qfq: do not free existing class in qfq_change_class() (bsc#1257236).
- CVE-2026-23001: macvlan: fix possible UAF in macvlan_forward_source() (bsc#1257232).

The following non security issues were fixed:

- mm, page_alloc, thp: prevent reclaim for __GFP_THISNODE THP allocations (bsc#1253087).
- net: hv_netvsc: reject RSS hash key programming without RX indirection table (bsc#1257473).
- net: tcp: allow zero-window ACK update the window (bsc#1254767).
- net: tcp: send zero-window ACK when no memory (bsc#1254767).
- scsi: storvsc: Process unsupported MODE_SENSE_10 (bsc#1257296).
- tcp: correct handling of extreme memory squeeze (bsc#1254767).
- x86: make page fault handling disable interrupts properly (git-fixes).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~5.14.21~150500.55.136.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~5.14.21~150500.55.136.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~5.14.21~150500.55.136.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150500.55.136.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150500.55.136.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150500.55.136.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150500.55.136.1.150500.6.67.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150500.55.136.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150500.55.136.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150500.55.136.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150500.55.136.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150500.55.136.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150500.55.136.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150500.55.136.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150500.55.136.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~5.14.21~150500.55.136.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150500.55.136.1", rls:"SLES15.0SP5"))) {
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

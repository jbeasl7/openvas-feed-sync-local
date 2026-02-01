# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20149.1");
  script_cve_id("CVE-2024-53164", "CVE-2025-38500", "CVE-2025-38554", "CVE-2025-38572", "CVE-2025-38588", "CVE-2025-38608", "CVE-2025-38616", "CVE-2025-38617", "CVE-2025-38618", "CVE-2025-38664", "CVE-2025-39682", "CVE-2025-39963", "CVE-2025-40204", "CVE-2025-40212");
  script_tag(name:"creation_date", value:"2026-01-30 04:34:32 +0000 (Fri, 30 Jan 2026)");
  script_version("2026-01-30T05:55:24+0000");
  script_tag(name:"last_modification", value:"2026-01-30 05:55:24 +0000 (Fri, 30 Jan 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-07 16:56:23 +0000 (Wed, 07 Jan 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20149-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20149-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620149-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246019");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248301");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248672");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249207");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249537");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252270");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256928");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023950.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel (Live Patch 0 for SUSE Linux Enterprise 16)' package(s) announced via the SUSE-SU-2026:20149-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the SUSE Linux Enterprise kernel 6.12.0-160000.5.1 fixes various security issues

The following security issues were fixed:

- CVE-2024-53164: net: sched: fix ordering of qlen adjustment (bsc#1246019).
- CVE-2025-38500: xfrm: interface: fix use-after-free after changing collect_md xfrm interface (bsc#1248672).
- CVE-2025-38554: mm: fix a UAF when vma->mm is freed after vma->vm_refcnt got dropped (bsc#1248301).
- CVE-2025-38572: ipv6: reject malicious packets in ipv6_gso_segment() (bsc#1248400).
- CVE-2025-38588: ipv6: prevent infinite loop in rt6_nlmsg_size() (bsc#1249241).
- CVE-2025-38608: bpf, ktls: Fix data corruption when using bpf_msg_pop_data() in ktls (bsc#1248670).
- CVE-2025-38616: tls: handle data disappearing from under the TLS ULP (bsc#1249537).
- CVE-2025-38617: net/packet: fix a race in packet_set_ring() and packet_notifier() (bsc#1249208).
- CVE-2025-38618: vsock: Do not allow binding to VMADDR_PORT_ANY (bsc#1249207).
- CVE-2025-38664: ice: Fix a null pointer dereference in ice_copy_and_init_pkg() (bsc#1248631).
- CVE-2025-39682: tls: fix handling of zero-length records on the rx_list (bsc#1250192).
- CVE-2025-39963: io_uring: fix incorrect io_kiocb reference in io_link_skb (bsc#1251982).
- CVE-2025-40204: sctp: Fix MAC comparison to be constant-time (bsc#1253437).
- CVE-2025-40212: nfsd: fix refcount leak in nfsd_set_fh_dentry() (bsc#1254196).

The following non security issues were fixed:

- Explicitly add module-common.c with vermagic and retpoline modinfo (bsc#1252270).
- powerpc64/modules: correctly iterate over stubs in setup_ftrace_ool_stubs (bsc#1251956).
- fix addr_bit_set() issue on big-endian machines (bsc#1256928).");

  script_tag(name:"affected", value:"'Linux Kernel (Live Patch 0 for SUSE Linux Enterprise 16)' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-6_12_0-160000_5-default", rpm:"kernel-livepatch-6_12_0-160000_5-default~5~160000.4.3", rls:"SLES16.0.0"))) {
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

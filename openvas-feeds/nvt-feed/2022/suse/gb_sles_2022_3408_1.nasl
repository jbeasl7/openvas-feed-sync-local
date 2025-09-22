# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3408.1");
  script_cve_id("CVE-2020-36516", "CVE-2021-4203", "CVE-2022-1012", "CVE-2022-20368", "CVE-2022-20369", "CVE-2022-21385", "CVE-2022-2588", "CVE-2022-26373", "CVE-2022-2639", "CVE-2022-2663", "CVE-2022-29581", "CVE-2022-2977", "CVE-2022-3028", "CVE-2022-36879", "CVE-2022-39188");
  script_tag(name:"creation_date", value:"2022-09-27 04:47:45 +0000 (Tue, 27 Sep 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-30 16:34:07 +0000 (Fri, 30 Sep 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3408-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3408-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223408-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180153");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188944");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199665");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201019");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201420");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202096");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202097");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202393");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202396");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202672");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202898");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203098");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203107");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-September/012386.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:3408-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP1 LTSS kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2020-36516: Fixed an issue in the mixed IPID assignment method where an attacker was able to inject data into or terminate a victim's TCP session (bnc#1196616).
- CVE-2021-4203: Fixed use-after-free read flaw that was found in sock_getsockopt() in net/core/sock.c due to SO_PEERCRED and SO_PEERGROUPS race with listen() (bnc#1194535).
- CVE-2022-1012: Fixed a memory leak problem that was found in the TCP source port generation algorithm in net/ipv4/tcp.c (bnc#1199482).
- CVE-2022-20368: Fixed slab-out-of-bounds access in packet_recvmsg() (bsc#1202346).
- CVE-2022-20369: Fixed out of bounds write in v4l2_m2m_querybuf of v4l2-mem2mem.c (bnc#1202347).
- CVE-2022-21385: Fixed a flaw in net_rds_alloc_sgs() that allowed unprivileged local users to crash the machine (bnc#1202897).
- CVE-2022-2588: Fixed use-after-free in cls_route (bsc#1202096).
- CVE-2022-26373: Fixed non-transparent sharing of return predictor targets between contexts in some Intel Processors (bnc#1201726).
- CVE-2022-2639: Fixed an integer coercion error that was found in the openvswitch kernel module (bnc#1202154).
- CVE-2022-2663: Fixed an issue that was found in nf_conntrack_irc where the message handling could be confused and incorrectly matches the message (bnc#1202097).
- CVE-2022-29581: Fixed improper update of reference count vulnerability in net/sched that allowed a local attacker to cause privilege escalation to root (bnc#1199665).
- CVE-2022-2977: Fixed reference counting for struct tpm_chip (bsc#1202672).
- CVE-2022-3028: Fixed race condition that was found in the IP framework for transforming packets (XFRM subsystem) (bnc#1202898).
- CVE-2022-36879: Fixed an issue in xfrm_expand_policies in net/xfrm/xfrm_policy.c where a refcount could be dropped twice (bnc#1201948).
- CVE-2022-39188: Fixed race condition in include/asm-generic/tlb.h where a device driver can free a page while it still has stale TLB entries (bnc#1203107).

The following non-security bugs were fixed:

- rpm: Fix parsing of rpm/macros.kernel-source on SLE12 (bsc#1201019).
- cifs: fix error paths in cifs_tree_connect() (bsc#1177440).
- cifs: fix uninitialized pointer in error case in dfs_cache_get_tgt_share (bsc#1188944).
- cifs: report error instead of invalid when revalidating a dentry fails (bsc#1177440).
- cifs: skip trailing separators of prefix paths (bsc#1188944).
- kernel-obs-build: include qemu_fw_cfg (boo#1201705)
- lightnvm: Remove lightnvm implemenation (bsc#1191881 bsc#1201420 ZDI-CAN-17325).
- md/bitmap: do not set sb values if can't pass sanity check (bsc#1197158).
- mm/rmap.c: do not reuse anon_vma if we just want a copy (git-fixes, bsc#1203098).
- mm/rmap: Fix anon_vma->degree ambiguity leading to double-reuse (git-fixes, bsc#1203098).
- net_sched: cls_route: disallow ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~150100.197.123.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~150100.197.123.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~150100.197.123.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~150100.197.123.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~150100.197.123.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~150100.197.123.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~150100.197.123.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~150100.197.123.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~150100.197.123.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~150100.197.123.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~150100.197.123.1", rls:"SLES15.0SP1"))) {
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

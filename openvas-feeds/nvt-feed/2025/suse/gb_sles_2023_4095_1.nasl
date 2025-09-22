# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4095.1");
  script_cve_id("CVE-2020-36766", "CVE-2023-1192", "CVE-2023-1206", "CVE-2023-1859", "CVE-2023-2177", "CVE-2023-23454", "CVE-2023-4004", "CVE-2023-40283", "CVE-2023-42753", "CVE-2023-4389", "CVE-2023-4622", "CVE-2023-4623", "CVE-2023-4881", "CVE-2023-4921");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-14 19:38:11 +0000 (Thu, 14 Sep 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4095-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4095-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234095-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207270");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210643");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210658");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213812");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214233");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214380");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214386");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215150");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215299");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215356");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2023-October/032196.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:4095-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2023-1206: Fixed a hash collision flaw in the IPv6 connection lookup table. A user located in the local network or with a high bandwidth connection can increase the CPU usage of the server that accepts IPV6 connections up to 95% (bsc#1212703).
- CVE-2023-42753: Fixed an array indexing vulnerability in the netfilter subsystem. This issue may have allowed a local user to crash the system or potentially escalate their privileges on the system. (bsc#1215150)
- CVE-2023-4389: Fixed a a double decrement of the reference count flaw in the btrfs filesystem a double decrement of the reference count, which may have allowed a local attacker with user privilege to crash the system or may lead to leaked internal kernel information. (bsc#1214351)
- CVE-2023-4921: Fixed a use-after-free vulnerability in the sch_qfq component which could be exploited to achieve local privilege escalation. (bsc#1215275)
- CVE-2023-23454: Fixed a type-confusion in the CBQ network scheduler (bsc#1207036).
- CVE-2023-4004: Fixed improper element removal netfilter nft_set_pipapo (bsc#1213812).
- CVE-2023-4622: Fixed a use-after-free vulnerability in the af_unix component which could be exploited to achieve local privilege escalation. (bsc#1215117)
- CVE-2023-4623: Fixed a use-after-free issue in the HFSC network scheduler which could be exploited to achieve local privilege escalation (bsc#1215115).
- CVE-2020-36766: Fixed an issue in drivers/media/cec/core/cec-api.c which could leaks one byte of kernel memory on specific hardware to unprivileged users. (bsc#1215299)
- CVE-2023-1859: Fixed a use-after-free flaw in Xen transport for 9pfs. This flaw could allow a local attacker to crash the system due to a race problem, possibly leading to a kernel information leak. (bsc#1210169)
- CVE-2023-2177: Fixed a null pointer dereference issue in the sctp network protocol which could allow a user to crash the system or potentially cause a denial of service. (bsc#1210643)
- CVE-2023-4881: Fixed a out-of-bounds write flaw in the netfilter subsystem that could lead to potential information disclosure or a denial of service (bsc#1215221).
- CVE-2023-40283: Fixed use-after-free in l2cap_sock_ready_cb (bsc#1214233).
- CVE-2023-1192: Fixed use-after-free in cifs_demultiplex_thread() (bsc#1208995).

The following non-security bugs were fixed:

- bnx2x: new flag for track HW resource allocation (bsc#1202845 bsc#1215322).
- locking/rwsem: Disable reader optimistic spinning (bnc#1176588).
- mkspec: Allow unsupported KMPs (bsc#1214386)
- scsi: qedf: Add synchronization between I/O completions and abort (bsc#1210658).
- x86/pkeys: Revert a5eff7259790 ('x86/pkeys: Add PKRU value to init_fpstate') (bsc#1215356).
- x86/srso: Do not probe microcode in a guest (git-fixes).
- x86/srso: Fix SBPB ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.3.18~150300.59.138.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.3.18~150300.59.138.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150300.59.138.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150300.59.138.1.150300.18.80.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150300.59.138.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150300.59.138.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150300.59.138.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150300.59.138.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150300.59.138.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150300.59.138.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150300.59.138.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150300.59.138.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150300.59.138.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.3.18~150300.59.138.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150300.59.138.1", rls:"SLES15.0SP3"))) {
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

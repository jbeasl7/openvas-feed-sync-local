# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2923.1");
  script_cve_id("CVE-2020-26558", "CVE-2021-0129", "CVE-2021-47126", "CVE-2021-47219", "CVE-2021-47291", "CVE-2021-47506", "CVE-2021-47520", "CVE-2021-47580", "CVE-2021-47598", "CVE-2021-47600", "CVE-2022-48792", "CVE-2022-48821", "CVE-2023-52686", "CVE-2023-52885", "CVE-2024-26583", "CVE-2024-26584", "CVE-2024-26585", "CVE-2024-36974", "CVE-2024-38559", "CVE-2024-39494", "CVE-2024-40937", "CVE-2024-41011", "CVE-2024-41059", "CVE-2024-41069", "CVE-2024-41090", "CVE-2024-42145");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-06 13:19:10 +0000 (Fri, 06 Sep 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2923-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2923-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242923-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224682");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224918");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226550");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226574");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228328");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228561");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228743");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-August/019201.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:2923-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2024-39494: ima: Fix use-after-free on a dentry's dname.name (bsc#1227716).
- CVE-2024-41069: ASoC: topology: Fix route memory corruption (bsc#1228644).
- CVE-2024-42145: IB/core: Implement a limit on UMAD receive List (bsc#1228743).
- CVE-2024-41059: hfsplus: fix uninit-value in copy_name (bsc#1228561).
- CVE-2023-52885: SUNRPC: Fix UAF in svc_tcp_listen_data_ready() (bsc#1227750).
- CVE-2022-48792: scsi: pm8001: Fix use-after-free for aborted SSP/STP sas_task (bsc#1228013).
- CVE-2024-41090: tap: add missing verification for short frame (bsc#1228328).
- CVE-2021-47291: ipv6: fix another slab-out-of-bounds in fib6_nh_flush_exceptions (bsc#1224918).
- CVE-2021-47126: ipv6: Fix KASAN: slab-out-of-bounds Read in fib6_nh_flush_exceptions (bsc#1221539).
- CVE-2024-41011: drm/amdkfd: do not allow mapping the MMIO HDP page with large pages (bsc#1228114).
- CVE-2021-47598: sch_cake: do not call cake_destroy() from cake_init() (bsc#1226574).
- CVE-2021-47580: scsi: scsi_debug: Fix type in min_t to avoid stack OOB (bsc#1226550).
- CVE-2021-47219: scsi: scsi_debug: Fix out-of-bound read in resp_report_tgtpgs() (bsc#1222824).
- CVE-2024-40937: gve: Clear napi->skb before dev_kfree_skb_any() (bsc#1227836).
- CVE-2021-0129: Improper access control in BlueZ may have allowed an authenticated user to potentially enable information disclosure via adjacent access (bsc#1186463).
- CVE-2020-26558: Fixed a flaw in the Bluetooth LE and BR/EDR secure pairing that could permit a nearby man-in-the-middle attacker to identify the Passkey used during pairing (bsc#1179610).
- CVE-2022-48821: misc: fastrpc: avoid double fput() on failed usercopy (bsc#1227976).
- CVE-2021-47506: nfsd: fix use-after-free due to delegation race (bsc#1225404).
- CVE-2021-47520: can: pch_can: pch_can_rx_normal: fix use after free (bsc#1225431).
- CVE-2024-26583: tls: fix use-after-free on failed backlog decryption (bsc#1220185).
- CVE-2024-26585: Fixed race between tx work scheduling and socket close (bsc#1220187).
- CVE-2021-47600: dm btree remove: fix use after free in rebalance_children() (bsc#1226575).
- CVE-2024-36974: net/sched: taprio: always validate TCA_TAPRIO_ATTR_PRIOMAP (bsc#1226519).

The following non-security bugs were fixed:

- Fix spurious WARNING caused by a qxl driver patch (bsc#1227213)
- X.509: Fix the parser of extended key usage for length (bsc#1218820 bsc#1226666).
- ocfs2: fix DIO failure due to insufficient transaction credits (bsc#1216834).
- powerpc/rtas: Prevent Spectre v1 gadget construction in sys_rtas() (bsc#1227487).
- powerpc/rtas: clean up includes (bsc#1227487).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150200.24.200.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150200.24.200.1.150200.9.103.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150200.24.200.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150200.24.200.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150200.24.200.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150200.24.200.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150200.24.200.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150200.24.200.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150200.24.200.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150200.24.200.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150200.24.200.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150200.24.200.1", rls:"SLES15.0SP2"))) {
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

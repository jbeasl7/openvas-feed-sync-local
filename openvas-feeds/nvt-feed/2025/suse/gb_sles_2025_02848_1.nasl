# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02848.1");
  script_cve_id("CVE-2022-50211", "CVE-2023-2176", "CVE-2023-52923", "CVE-2023-52927", "CVE-2024-53057", "CVE-2024-53164", "CVE-2024-57947", "CVE-2025-37797", "CVE-2025-37798", "CVE-2025-38079", "CVE-2025-38120", "CVE-2025-38177", "CVE-2025-38181", "CVE-2025-38200", "CVE-2025-38212", "CVE-2025-38213", "CVE-2025-38257", "CVE-2025-38494", "CVE-2025-38495", "CVE-2025-38497");
  script_tag(name:"creation_date", value:"2025-08-20 04:10:46 +0000 (Wed, 20 Aug 2025)");
  script_version("2025-08-20T05:40:05+0000");
  script_tag(name:"last_modification", value:"2025-08-20 05:40:05 +0000 (Wed, 20 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-22 17:55:23 +0000 (Fri, 22 Nov 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02848-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02848-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502848-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233551");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236104");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242417");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246029");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247349");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041248.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:02848-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security bugfixes.

The following security bugs were fixed:

- CVE-2022-50211: md-raid10: fix KASAN warning (bsc#1245140).
- CVE-2023-2176: Fixed an out-of-boundary read in compare_netdev_and_ip in drivers/infiniband/core/cma.c in RDMA (bsc#1210629).
- CVE-2023-52923: netfilter: nf_tables: split async and sync catchall in two functions (bsc#1236104).
- CVE-2023-52927: netfilter: allow exp not to be removed in nf_ct_find_expectation (bsc#1239644).
- CVE-2024-53057: net/sched: stop qdisc_tree_reduce_backlog on TC_H_ROOT (bsc#1233551).
- CVE-2024-53164: net: sched: fix ordering of qlen adjustment (bsc#1234863).
- CVE-2025-37797: net_sched: hfsc: Fix a UAF vulnerability in class handling (bsc#1242417).
- CVE-2025-38079: crypto: algif_hash - fix double free in hash_accept (bsc#1245217).
- CVE-2025-38181: calipso: Fix null-ptr-deref in calipso_req_{set,del}attr() (bsc#1246000).
- CVE-2025-38200: i40e: fix MMIO write access to an invalid page in i40e_clear_hw (bsc#1246045).
- CVE-2025-38212: ipc: fix to protect IPCS lookups using RCU (bsc#1246029).
- CVE-2025-38213: vgacon: Add check for vc_origin address range in vgacon_scroll() (bsc#1246037).
- CVE-2025-38257: s390/pkey: Prevent overflow in size calculation for memdup_user() (bsc#1246186).
- CVE-2025-38494: HID: core: do not bypass hid_hw_raw_request (bsc#1247349).
- CVE-2025-38495: HID: core: ensure the allocated report buffer can contain the reserved report ID (bsc#1247348).
- CVE-2025-38497: usb: gadget: configfs: Fix OOB read on empty string write (bsc#1247347).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.3.18~150300.59.215.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.3.18~150300.59.215.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150300.59.215.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150300.59.215.1.150300.18.128.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150300.59.215.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150300.59.215.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150300.59.215.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150300.59.215.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150300.59.215.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150300.59.215.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150300.59.215.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150300.59.215.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150300.59.215.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.3.18~150300.59.215.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150300.59.215.1", rls:"SLES15.0SP3"))) {
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

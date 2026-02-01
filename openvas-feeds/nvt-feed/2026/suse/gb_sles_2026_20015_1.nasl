# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20015.1");
  script_cve_id("CVE-2022-50253", "CVE-2025-37916", "CVE-2025-38084", "CVE-2025-38085", "CVE-2025-38321", "CVE-2025-38728", "CVE-2025-39805", "CVE-2025-39819", "CVE-2025-39822", "CVE-2025-39831", "CVE-2025-39859", "CVE-2025-39897", "CVE-2025-39917", "CVE-2025-39944", "CVE-2025-39961", "CVE-2025-39980", "CVE-2025-39990", "CVE-2025-40001", "CVE-2025-40003", "CVE-2025-40006", "CVE-2025-40021", "CVE-2025-40024", "CVE-2025-40027", "CVE-2025-40031", "CVE-2025-40033", "CVE-2025-40038", "CVE-2025-40047", "CVE-2025-40053", "CVE-2025-40055", "CVE-2025-40059", "CVE-2025-40064", "CVE-2025-40070", "CVE-2025-40074", "CVE-2025-40075", "CVE-2025-40081", "CVE-2025-40083", "CVE-2025-40086", "CVE-2025-40098", "CVE-2025-40101", "CVE-2025-40102", "CVE-2025-40105", "CVE-2025-40107", "CVE-2025-40109", "CVE-2025-40110", "CVE-2025-40111", "CVE-2025-40115", "CVE-2025-40116", "CVE-2025-40118", "CVE-2025-40120", "CVE-2025-40121", "CVE-2025-40127", "CVE-2025-40129", "CVE-2025-40132", "CVE-2025-40133", "CVE-2025-40134", "CVE-2025-40135", "CVE-2025-40139", "CVE-2025-40140", "CVE-2025-40141", "CVE-2025-40142", "CVE-2025-40149", "CVE-2025-40153", "CVE-2025-40154", "CVE-2025-40156", "CVE-2025-40157", "CVE-2025-40158", "CVE-2025-40159", "CVE-2025-40161", "CVE-2025-40162", "CVE-2025-40164", "CVE-2025-40165", "CVE-2025-40166", "CVE-2025-40168", "CVE-2025-40169", "CVE-2025-40171", "CVE-2025-40172", "CVE-2025-40173", "CVE-2025-40175", "CVE-2025-40176", "CVE-2025-40177", "CVE-2025-40178", "CVE-2025-40180", "CVE-2025-40183", "CVE-2025-40185", "CVE-2025-40186", "CVE-2025-40187", "CVE-2025-40188", "CVE-2025-40192", "CVE-2025-40194", "CVE-2025-40196", "CVE-2025-40197", "CVE-2025-40198", "CVE-2025-40200", "CVE-2025-40201", "CVE-2025-40202", "CVE-2025-40203", "CVE-2025-40204", "CVE-2025-40205", "CVE-2025-40206", "CVE-2025-40207");
  script_tag(name:"creation_date", value:"2026-01-12 04:33:21 +0000 (Mon, 12 Jan 2026)");
  script_version("2026-01-28T05:49:43+0000");
  script_tag(name:"last_modification", value:"2026-01-28 05:49:43 +0000 (Wed, 28 Jan 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-27 19:52:27 +0000 (Tue, 27 Jan 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20015-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20015-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620015-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243474");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245498");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245499");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246328");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247500");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249397");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249977");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250176");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250252");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251817");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252054");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252063");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252301");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252352");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252357");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252681");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252776");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252794");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252808");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252817");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252919");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252923");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252928");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253176");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253238");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253324");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253328");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253352");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253362");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253367");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253369");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253386");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253402");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253403");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253407");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253408");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253409");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253412");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253421");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253425");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253426");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253438");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253443");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253445");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253448");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253449");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253450");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253451");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253455");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253472");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253622");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253643");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254308");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254315");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023727.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2026:20015-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 16.0 kernel was updated to fix various security issues

The following security issues were fixed:

- CVE-2022-50253: bpf: make sure skb->len != 0 when redirecting to a tunneling device (bsc#1249912).
- CVE-2025-37916: pds_core: remove write-after-free of client_id (bsc#1243474).
- CVE-2025-38084: mm/hugetlb: unshare page tables during VMA split, not before (bsc#1245431 bsc#1245498).
- CVE-2025-38085: mm/hugetlb: fix huge_pmd_unshare() vs GUP-fast race (bsc#1245431 bsc#1245499).
- CVE-2025-38321: smb: Log an error when close_all_cached_dirs fails (bsc#1246328).
- CVE-2025-38728: smb3: fix for slab out of bounds on mount to ksmbd (bsc#1249256).
- CVE-2025-39805: net: macb: fix unregister_netdev call order in macb_remove() (bsc#1249982).
- CVE-2025-39819: fs/smb: Fix inconsistent refcnt update (bsc#1250176).
- CVE-2025-39822: io_uring/kbuf: fix signedness in this_len calculation (bsc#1250034).
- CVE-2025-39831: fbnic: Move phylink resume out of service_task and into open/close (bsc#1249977).
- CVE-2025-39859: ptp: ocp: fix use-after-free bugs causing by ptp_ocp_watchdog (bsc#1250252).
- CVE-2025-39897: net: xilinx: axienet: Add error handling for RX metadata pointer retrieval (bsc#1250746).
- CVE-2025-39917: bpf: Fix out-of-bounds dynptr write in bpf_crypto_crypt (bsc#1250723).
- CVE-2025-39944: octeontx2-pf: Fix use-after-free bugs in otx2_sync_tstamp() (bsc#1251120).
- CVE-2025-39961: iommu/amd/pgtbl: Fix possible race while increase page table level (bsc#1251817).
- CVE-2025-39980: nexthop: Forbid FDB status change while nexthop is in a group (bsc#1252063).
- CVE-2025-39990: bpf: Check the helper function is valid in get_helper_proto (bsc#1252054).
- CVE-2025-40001: scsi: mvsas: Fix use-after-free bugs in mvs_work_queue (bsc#1252303).
- CVE-2025-40003: net: mscc: ocelot: Fix use-after-free caused by cyclic delayed work (bsc#1252301).
- CVE-2025-40006: mm/hugetlb: fix folio is still mapped when deleted (bsc#1252342).
- CVE-2025-40021: tracing: dynevent: Add a missing lockdown check on dynevent (bsc#1252681).
- CVE-2025-40024: vhost: Take a reference on the task in struct vhost_task (bsc#1252686).
- CVE-2025-40027: net/9p: fix double req put in p9_fd_cancelled (bsc#1252763).
- CVE-2025-40031: tee: fix register_shm_helper() (bsc#1252779).
- CVE-2025-40033: remoteproc: pru: Fix potential NULL pointer dereference in pru_rproc_set_ctable() (bsc#1252824).
- CVE-2025-40038: KVM: SVM: Skip fastpath emulation on VM-Exit if next RIP isn't valid (bsc#1252817).
- CVE-2025-40047: io_uring/waitid: always prune wait queue entry in io_waitid_wait() (bsc#1252790).
- CVE-2025-40053: net: dlink: handle copy_thresh allocation failure (bsc#1252808).
- CVE-2025-40055: ocfs2: fix double free in user_cluster_connect() (bsc#1252821).
- CVE-2025-40059: coresight: Fix incorrect handling for return value of devm_kzalloc (bsc#1252809).
- CVE-2025-40064: smc: Fix ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~6.12.0~160000.8.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~6.12.0~160000.8.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~6.12.0~160000.8.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~6.12.0~160000.8.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~6.12.0~160000.8.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-extra", rpm:"kernel-64kb-extra~6.12.0~160000.8.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~6.12.0~160000.8.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~6.12.0~160000.8.1.160000.2.5", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~6.12.0~160000.8.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~6.12.0~160000.8.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-livepatch", rpm:"kernel-default-livepatch~6.12.0~160000.8.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-vdso", rpm:"kernel-default-vdso~6.12.0~160000.8.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~6.12.0~160000.8.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~6.12.0~160000.8.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs-html", rpm:"kernel-docs-html~6.12.0~160000.8.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall", rpm:"kernel-kvmsmall~6.12.0~160000.8.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel", rpm:"kernel-kvmsmall-devel~6.12.0~160000.8.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-vdso", rpm:"kernel-kvmsmall-vdso~6.12.0~160000.8.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~6.12.0~160000.8.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-qa", rpm:"kernel-obs-qa~6.12.0~160000.8.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~6.12.0~160000.8.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~6.12.0~160000.8.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~6.12.0~160000.8.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~6.12.0~160000.8.1", rls:"SLES16.0.0"))) {
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

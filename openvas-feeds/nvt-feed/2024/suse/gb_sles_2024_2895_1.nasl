# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2895.1");
  script_cve_id("CVE-2016-20022", "CVE-2021-43389", "CVE-2021-4439", "CVE-2021-47219", "CVE-2021-47520", "CVE-2021-47580", "CVE-2021-47600", "CVE-2023-52752", "CVE-2023-52881", "CVE-2024-26923", "CVE-2024-36964", "CVE-2024-38599", "CVE-2024-42145");
  script_tag(name:"creation_date", value:"2024-08-14 04:25:53 +0000 (Wed, 14 Aug 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-24 01:12:36 +0000 (Fri, 24 May 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2895-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2895-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242895-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197439");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226550");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228743");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-August/019186.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:2895-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2024-42145: IB/core: Implement a limit on UMAD receive List (bsc#1228743)
- CVE-2021-47580: scsi: scsi_debug: Fix type in min_t to avoid stack OOB (bsc#1226550).
- CVE-2021-47219: scsi: scsi_debug: Fix out-of-bound read in resp_report_tgtpgs() (bsc#1222824).
- CVE-2021-47520: can: pch_can: pch_can_rx_normal: fix use after free (bsc#1225431).
- CVE-2021-47600: dm btree remove: fix use after free in rebalance_children() (bsc#1226575).
- CVE-2023-52881: tcp: do not accept ACK of bytes we never sent (bsc#1225611).
- CVE-2024-38599: jffs2: prevent xattr node from overflowing the eraseblock (bsc#1226848).
- CVE-2023-52752: smb: client: fix use-after-free bug in cifs_debug_data_proc_show() (bsc#1225487).
- CVE-2024-36964: fs/9p: only translate RWX permissions for plain 9P2000 (bsc#1225866).
- CVE-2024-26923: Fixed false-positive lockdep splat for spin_lock() in __unix_gc() (bsc#1223384).

The following non-security bugs were fixed:

- af_unix: Do not use atomic ops for unix_sk(sk)->inflight (bsc#1223384).
- af_unix: Replace BUG_ON() with WARN_ON_ONCE() (bsc#1223384).
- af_unix: annote lockless accesses to unix_tot_inflight & gc_in_progress (bsc#1223384).
- kvm: prevent kvm_clock time-warps (bsc#1197439).
- net: unix: properly re-increment inflight counter of GC discarded candidates (bsc#1223384).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~108.159.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~108.159.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~108.159.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~108.159.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~108.159.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~108.159.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~108.159.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~108.159.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~108.159.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~108.159.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~108.159.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~108.159.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~108.159.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~108.159.1", rls:"SLES11.0SP4"))) {
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

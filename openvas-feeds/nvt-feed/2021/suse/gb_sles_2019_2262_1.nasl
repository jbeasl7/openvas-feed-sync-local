# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2262.1");
  script_cve_id("CVE-2018-20855", "CVE-2019-1125", "CVE-2019-11810", "CVE-2019-13631", "CVE-2019-13648", "CVE-2019-14283", "CVE-2019-14284");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-07 18:42:14 +0000 (Tue, 07 May 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2262-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2262-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192262-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130972");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1139358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141402");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142023");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142098");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144273");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144288");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-September/005864.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:2262-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP1 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2019-1125: Enable Spectre v1 swapgs mitigations (bsc#1139358).
- CVE-2018-20855: An issue was discovered in create_qp_common in drivers/infiniband/hw/mlx5/qp.c, mlx5_ib_create_qp_resp was never initialized, resulting in a leak of stack memory to userspace (bsc#1143045).
- CVE-2019-14284: The drivers/block/floppy.c allowed a denial of service by setup_format_params division-by-zero. Two consecutive ioctls can trigger the bug: the first one should set the drive geometry with .sect and .rate values that make F_SECT_PER_TRACK be zero. Next, the floppy format operation should be called. It can be triggered by an unprivileged local user even when a floppy disk has not been inserted. NOTE: QEMU creates the floppy device by default (bsc#1143189).
- CVE-2019-14283: The function set_geometry in drivers/block/floppy.c did not validate the sect and head fields, as demonstrated by an integer overflow and out-of-bounds read. It can be triggered by an unprivileged local user when a floppy disk has been inserted. NOTE: QEMU creates the floppy device by default (bsc#1143191).
- CVE-2019-11810: A NULL pointer dereference can occur when megasas_create_frame_pool() fails in megasas_alloc_cmds() in drivers/scsi/megaraid/megaraid_sas_base.c. This causes a Denial of Service, related to a use-after-free (bsc#1134399).
- CVE-2019-13648: In the Linux kernel on the powerpc platform, when hardware transactional memory is disabled, a local user can cause a denial of service (TM Bad Thing exception and system crash) via a sigreturn() system call that sends a crafted signal frame. This affects arch/powerpc/kernel/signal_32.c and arch/powerpc/kernel/signal_64.c (bnc#1142254).
- CVE-2019-13631: In parse_hid_report_descriptor in drivers/input/tablet/gtco.c, a malicious USB device can send an HID report that triggers an out-of-bounds write during generation of debugging messages (bsc#1142023).

The following non-security bugs were fixed:

- bcache: Revert 'bcache: fix high CPU occupancy during journal' (bsc#1140652, bsc#1144288).
- bcache: Revert 'bcache: free heap cache_set->flush_btree in bch_journal_free' (bsc#1140652, bsc#1144288).
- bcache: add reclaimed_journal_buckets to struct cache_set (bsc#1140652, bsc#1144288).
- bcache: fix race in btree_flush_write() (bsc#1140652, bsc#1144288).
- bcache: fix stack corruption by PRECEDING_KEY() (bsc#1130972, bsc#1144257).
- bcache: only set BCACHE_DEV_WB_RUNNING when cached device attached (bsc#1130972, bsc#1144273).
- bcache: performance improvement for btree_flush_write() (bsc#1140652, bsc#1144288).
- bcache: remove retry_flush_write from struct cache_set (bsc#1140652, bsc#1144288).
- mm: check VMA flags to avoid invalid PROT_NONE NUMA balancing (bsc#1142098).
- powerpc/watchpoint: Restore NV GPRs while returning from ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.74~60.64.121.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.74~60.64.121.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.74~60.64.121.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.74~60.64.121.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.74~60.64.121.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.74~60.64.121.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.74~60.64.121.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.74~60.64.121.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.74~60.64.121.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.74~60.64.121.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.74~60.64.121.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.74~60.64.121.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.74~60.64.121.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.74~60.64.121.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.74~60.64.121.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.74~60.64.121.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.74~60.64.121.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_121-default", rpm:"kgraft-patch-3_12_74-60_64_121-default~1~2.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_121-xen", rpm:"kgraft-patch-3_12_74-60_64_121-xen~1~2.3.1", rls:"SLES12.0SP1"))) {
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

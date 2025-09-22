# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.14157.1");
  script_cve_id("CVE-2015-9289", "CVE-2018-20855", "CVE-2019-1125", "CVE-2019-11810", "CVE-2019-13631", "CVE-2019-14283", "CVE-2019-14284");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:20 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-07 18:42:14 +0000 (Tue, 07 May 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:14157-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:14157-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-201914157-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1139358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140965");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141402");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142023");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143191");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-August/005859.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:14157-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2019-14284: The drivers/block/floppy.c allowed a denial of service by setup_format_params division-by-zero. Two consecutive ioctls can trigger the bug: the first one should set the drive geometry with .sect and .rate values that make F_SECT_PER_TRACK be zero. Next, the floppy format operation should be called. It can be triggered by an unprivileged local user even when a floppy disk has not been inserted. NOTE: QEMU creates the floppy device by default (bsc#1143189).
- CVE-2019-14283: The function set_geometry in drivers/block/floppy.c did not validate the sect and head fields, as demonstrated by an integer overflow and out-of-bounds read. It can be triggered by an unprivileged local user when a floppy disk has been inserted. NOTE: QEMU creates the floppy device by default (bsc#1143191).
- CVE-2019-13631: In parse_hid_report_descriptor in drivers/input/tablet/gtco.c, a malicious USB device can send an HID report that triggers an out-of-bounds write during generation of debugging messages (bsc#1142023).
- CVE-2019-11810: A NULL pointer dereference can occur when megasas_create_frame_pool() fails in megasas_alloc_cmds() in drivers/scsi/megaraid/megaraid_sas_base.c. This causes a Denial of Service, related to a use-after-free (bsc#1134399).
- CVE-2019-1125: Enable Spectre v1 swapgs mitigations (bsc#1139358).
- CVE-2018-20855: An issue was discovered in create_qp_common in drivers/infiniband/hw/mlx5/qp.c, mlx5_ib_create_qp_resp was never initialized, resulting in a leak of stack memory to userspace (bsc#1143045).
- CVE-2015-9289: A buffer overflow occurs when checking userspace params in drivers/media/dvb-frontends/cx24116.c. The maximum size for a DiSEqC command is 6, according to the userspace API. However, the code allowed larger values such as 23 (bsc#1143179).

The following non-security bugs were fixed:

- fix detection of race between fcntl-setlk and close (bsc#1140965).
- ocfs2: add first lock wait time in locking_state (bsc#1134390).
- ocfs2: add last unlock times in locking_state (bsc#1134390).
- ocfs2: add locking filter debugfs file (bsc#1134390).
- powerpc/watchpoint: Restore NV GPRs while returning from exception (bsc#1140945,bsc#1141401,bsc#1141402,bsc#1141452,bsc#1141453,bsc#1141454).
- xen-netfront: use napi_complete() correctly to prevent Rx stalling (bsc#1138744).");

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

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~108.101.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~108.101.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~108.101.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~108.101.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~108.101.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem", rpm:"kernel-bigmem~3.0.101~108.101.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-base", rpm:"kernel-bigmem-base~3.0.101~108.101.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-devel", rpm:"kernel-bigmem-devel~3.0.101~108.101.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~108.101.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~108.101.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~108.101.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~108.101.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~108.101.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~108.101.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~108.101.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~108.101.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~108.101.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~108.101.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~108.101.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~108.101.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~108.101.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~108.101.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~108.101.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~108.101.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~108.101.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~108.101.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~108.101.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~108.101.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~108.101.1", rls:"SLES11.0SP4"))) {
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

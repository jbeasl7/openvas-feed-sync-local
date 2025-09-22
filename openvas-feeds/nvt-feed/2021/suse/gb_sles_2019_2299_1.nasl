# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2299.1");
  script_cve_id("CVE-2017-18551", "CVE-2018-20855", "CVE-2018-20856", "CVE-2019-10207", "CVE-2019-1125", "CVE-2019-11810", "CVE-2019-13631", "CVE-2019-14283", "CVE-2019-14284", "CVE-2019-15117", "CVE-2019-15118", "CVE-2019-3819");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-28 16:30:36 +0000 (Wed, 28 Aug 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2299-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2299-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192299-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130972");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1139358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141402");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142023");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142098");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142857");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144273");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144288");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146163");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-September/005881.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:2299-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2019-3819: A flaw was fixed in the function hid_debug_events_read() in drivers/hid/hid-debug.c file which may have enter an infinite loop with certain parameters passed from a userspace. A local privileged user ('root') could have caused a system lock up and a denial of service (bnc#1123161).
- CVE-2019-15118: Fixed kernel stack exhaustion in check_input_term in sound/usb/mixer.c via mishandled recursion (bnc#1145922).
- CVE-2019-15117: Fixed out-of-bounds memory access in parse_audio_mixer_unit in sound/usb/mixer.c via mishandled short descriptor (bnc#1145920).
- CVE-2019-14284: The drivers/block/floppy.c allowed a denial of service by setup_format_params division-by-zero. Two consecutive ioctls can trigger the bug: the first one should set the drive geometry with .sect and .rate values that make F_SECT_PER_TRACK be zero. Next, the floppy format operation should be called. It can be triggered by an unprivileged local user even when a floppy disk has not been inserted. NOTE: QEMU creates the floppy device by default (bsc#1143189).
- CVE-2019-14283: The function set_geometry in drivers/block/floppy.c did not validate the sect and head fields, as demonstrated by an integer overflow and out-of-bounds read. It can be triggered by an unprivileged local user when a floppy disk has been inserted. NOTE: QEMU creates the floppy device by default (bsc#1143191).
- CVE-2019-13631: In parse_hid_report_descriptor in drivers/input/tablet/gtco.c, a malicious USB device can send an HID report that triggers an out-of-bounds write during generation of debugging messages (bsc#1142023).
- CVE-2019-11810: A NULL pointer dereference can occur when megasas_create_frame_pool() fails in megasas_alloc_cmds() in drivers/scsi/megaraid/megaraid_sas_base.c. This causes a Denial of Service, related to a use-after-free (bsc#1134399).
- CVE-2019-1125: Enable Spectre v1 swapgs mitigations (bsc#1139358).
- CVE-2019-10207: Check for missing tty operations in bluetooth/hci_uart (bsc#1142857).
- CVE-2018-20856: Fixed a use-after-free issue in block/blk-core.c, where certain error case are mishandled (bnc#1143048).
- CVE-2018-20855: An issue was discovered in create_qp_common in drivers/infiniband/hw/mlx5/qp.c, mlx5_ib_create_qp_resp was never initialized, resulting in a leak of stack memory to userspace (bsc#1143045).
- CVE-2017-18551: An issue was discovered in drivers/i2c/i2c-core-smbus.c in the Linux kernel There was an out of bounds write in the function i2c_smbus_xfer_emulated (bnc#1146163).


The following non-security bugs were fixed:

- bcache: add reclaimed_journal_buckets to struct cache_set (bsc#1140652, bsc#1144288).
- bcache: fix race in btree_flush_write() (bsc#1140652, bsc#1144288).
- bcache: fix stack corruption by PRECEDING_KEY() (bsc#1130972, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.121~92.120.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.121~92.120.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.121~92.120.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.121~92.120.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.121~92.120.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.121~92.120.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.121~92.120.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.121~92.120.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_120-default", rpm:"kgraft-patch-4_4_121-92_120-default~1~3.3.1", rls:"SLES12.0SP2"))) {
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

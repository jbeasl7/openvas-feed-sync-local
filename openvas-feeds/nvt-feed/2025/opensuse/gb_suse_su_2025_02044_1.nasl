# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.02044.1");
  script_cve_id("CVE-2025-6019");
  script_tag(name:"creation_date", value:"2025-06-23 04:15:28 +0000 (Mon, 23 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-19 12:15:19 +0000 (Thu, 19 Jun 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:02044-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02044-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502044-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243285");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-June/040402.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libblockdev' package(s) announced via the SUSE-SU-2025:02044-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libblockdev fixes the following issues:

- CVE-2025-6019: Suppress privilege escalation during xfs fs resize (bsc#1243285).");

  script_tag(name:"affected", value:"'libblockdev' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"libbd_btrfs-devel", rpm:"libbd_btrfs-devel~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_btrfs2", rpm:"libbd_btrfs2~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_crypto-devel", rpm:"libbd_crypto-devel~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_crypto2", rpm:"libbd_crypto2~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_dm-devel", rpm:"libbd_dm-devel~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_dm2", rpm:"libbd_dm2~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_fs-devel", rpm:"libbd_fs-devel~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_fs2", rpm:"libbd_fs2~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_kbd-devel", rpm:"libbd_kbd-devel~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_kbd2", rpm:"libbd_kbd2~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_loop-devel", rpm:"libbd_loop-devel~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_loop2", rpm:"libbd_loop2~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_lvm-dbus-devel", rpm:"libbd_lvm-dbus-devel~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_lvm-dbus2", rpm:"libbd_lvm-dbus2~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_lvm-devel", rpm:"libbd_lvm-devel~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_lvm2", rpm:"libbd_lvm2~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_mdraid-devel", rpm:"libbd_mdraid-devel~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_mdraid2", rpm:"libbd_mdraid2~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_mpath-devel", rpm:"libbd_mpath-devel~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_mpath2", rpm:"libbd_mpath2~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_part-devel", rpm:"libbd_part-devel~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_part2", rpm:"libbd_part2~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_swap-devel", rpm:"libbd_swap-devel~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_swap2", rpm:"libbd_swap2~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_utils-devel", rpm:"libbd_utils-devel~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_utils2", rpm:"libbd_utils2~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_vdo-devel", rpm:"libbd_vdo-devel~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_vdo2", rpm:"libbd_vdo2~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev", rpm:"libblockdev~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-devel", rpm:"libblockdev-devel~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev2", rpm:"libblockdev2~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libblockdev", rpm:"python3-libblockdev~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-BlockDev-2_0", rpm:"typelib-1_0-BlockDev-2_0~2.26~150400.3.5.1", rls:"openSUSELeap15.6"))) {
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

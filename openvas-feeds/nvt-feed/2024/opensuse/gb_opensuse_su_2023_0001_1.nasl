# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833375");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2022-35978");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-17 14:16:24 +0000 (Wed, 17 Aug 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:47:32 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for minetest (openSUSE-SU-2023:0001-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0001-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6BEL53A6YRA752TFXGECQDT4XJ7UK6P5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'minetest'
  package(s) announced via the openSUSE-SU-2023:0001-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for minetest fixes the following issues:

     Update to version 5.6.0

  * Fix CVE-2022-35978 ( boo#1202423 ): Mod scripts can escape sandbox in
         single player mode

  * `name` in game.conf is deprecated for the game title, use `title`
         instead

  * Add depth sorting for node faces

  * Various bug fixes

  - Introduced mbranch-protection=none CXX flag to resolve boo#1193141
       (aarch64).

     Update to version 5.5.0 &amp  5.5.1:

  * This release switches from Irrlicht to our own fork called IrrlichtMt.

  * Full log for version 5.5.1:

  * This is a maintenance release based on 5.5.0, it contains bugfixes but
         no new features.

  - Added hardening to systemd service(s) (boo#1181400).

  - Update to version 5.4.1:

  * This is a maintenance release based on 5.4.0, it contains bugfixes but
         no new features.

  - Update to version 5.4.0

  * Removed support for bumpmapping, generated normal maps and parallax
         occlusion

  * By default, the crosshair will now change to an 'X' when pointing to
         objects

  * Prevent players accessing inventories of other players

  * Prevent interacting with items out of the hotbar

  * Prevent players from being able to modify ItemStack meta

  * Formspec improvements, including a scrolling GUI element

  * Performance improvements to the Server and API

  * Many bug fixes and small features

  - Now requires desktop-file-utils version  = 0.25.");

  script_tag(name:"affected", value:"'minetest' package(s) on openSUSE Backports SLE-15-SP4.");

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

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"minetest", rpm:"minetest~5.6.0~bp154.2.3.5", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"minetest-debuginfo", rpm:"minetest-debuginfo~5.6.0~bp154.2.3.5", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"minetest-debugsource", rpm:"minetest-debugsource~5.6.0~bp154.2.3.5", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"minetestserver", rpm:"minetestserver~5.6.0~bp154.2.3.5", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"minetestserver-debuginfo", rpm:"minetestserver-debuginfo~5.6.0~bp154.2.3.5", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"minetest-data", rpm:"minetest-data~5.6.0~bp154.2.3.5", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"minetest-lang", rpm:"minetest-lang~5.6.0~bp154.2.3.5", rls:"openSUSEBackportsSLE-15-SP4"))) {
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

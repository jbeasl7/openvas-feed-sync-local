# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856386");
  script_cve_id("CVE-2024-40724");
  script_tag(name:"creation_date", value:"2024-08-28 04:00:33 +0000 (Wed, 28 Aug 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-07 20:15:57 +0000 (Wed, 07 Aug 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:2984-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2984-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242984-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228204");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-August/036643.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libqt5-qt3d' package(s) announced via the SUSE-SU-2024:2984-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libqt5-qt3d fixes the following issues:

- CVE-2024-40724: Fixed a heap-based buffer overflow in the PLY importer class (bsc#1228204)
- Checked for a nullptr returned from the shader manager
- Fill image with transparency by default to avoid having junk if it's not filled properly before the first paint call
- Fixed QTextureAtlas parenting that could lead to crashes due to being used after free'd");

  script_tag(name:"affected", value:"'libqt5-qt3d' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libQt53DAnimation-devel", rpm:"libQt53DAnimation-devel~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DAnimation5", rpm:"libQt53DAnimation5~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DCore-devel", rpm:"libQt53DCore-devel~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DCore5", rpm:"libQt53DCore5~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DExtras-devel", rpm:"libQt53DExtras-devel~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DExtras5", rpm:"libQt53DExtras5~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DInput-devel", rpm:"libQt53DInput-devel~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DInput5", rpm:"libQt53DInput5~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DLogic-devel", rpm:"libQt53DLogic-devel~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DLogic5", rpm:"libQt53DLogic5~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuick-devel", rpm:"libQt53DQuick-devel~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuick5", rpm:"libQt53DQuick5~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuickAnimation-devel", rpm:"libQt53DQuickAnimation-devel~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuickAnimation5", rpm:"libQt53DQuickAnimation5~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuickExtras-devel", rpm:"libQt53DQuickExtras-devel~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuickExtras5", rpm:"libQt53DQuickExtras5~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuickInput-devel", rpm:"libQt53DQuickInput-devel~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuickInput5", rpm:"libQt53DQuickInput5~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuickRender-devel", rpm:"libQt53DQuickRender-devel~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuickRender5", rpm:"libQt53DQuickRender5~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuickScene2D-devel", rpm:"libQt53DQuickScene2D-devel~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuickScene2D5", rpm:"libQt53DQuickScene2D5~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DRender-devel", rpm:"libQt53DRender-devel~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DRender5", rpm:"libQt53DRender5~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qt3d-devel", rpm:"libqt5-qt3d-devel~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qt3d-examples", rpm:"libqt5-qt3d-examples~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qt3d-imports", rpm:"libqt5-qt3d-imports~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qt3d-private-headers-devel", rpm:"libqt5-qt3d-private-headers-devel~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qt3d-tools", rpm:"libqt5-qt3d-tools~5.15.12+kde0~150600.3.3.1", rls:"openSUSELeap15.6"))) {
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

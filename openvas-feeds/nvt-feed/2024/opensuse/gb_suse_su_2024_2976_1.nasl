# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856392");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-40724");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-07 20:15:57 +0000 (Wed, 07 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-28 04:01:18 +0000 (Wed, 28 Aug 2024)");
  script_name("openSUSE: Security Advisory for libqt5 (SUSE-SU-2024:2976-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2976-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/SCBP7JTM2LZZ6VT4X2LHT5TJ5FYMQUMC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libqt5'
  package(s) announced via the SUSE-SU-2024:2976-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libqt5-qt3d fixes the following issues:

  * CVE-2024-40724: Fixed heap-based buffer overflow in the PLY importer class
      in assimp (bsc#1228204)

  Other fixes: \- Check for a nullptr returned from the shader manager \- Fill
  image with transparency by default to avoid having junk if it's not filled
  properly before the first paint call \- Fix QTextureAtlas parenting that could
  lead to crashes due to being used after free'd.");

  script_tag(name:"affected", value:"'libqt5' package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"libQt53DExtras-devel", rpm:"libQt53DExtras-devel~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DInput-devel", rpm:"libQt53DInput-devel~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DCore-devel", rpm:"libQt53DCore-devel~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuickRender5", rpm:"libQt53DQuickRender5~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qt3d-debuginfo", rpm:"libqt5-qt3d-debuginfo~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuickAnimation5", rpm:"libQt53DQuickAnimation5~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuickScene2D5-debuginfo", rpm:"libQt53DQuickScene2D5-debuginfo~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuickRender-devel", rpm:"libQt53DQuickRender-devel~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DAnimation-devel", rpm:"libQt53DAnimation-devel~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qt3d-devel", rpm:"libqt5-qt3d-devel~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qt3d-imports", rpm:"libqt5-qt3d-imports~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DInput5-debuginfo", rpm:"libQt53DInput5-debuginfo~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuickExtras-devel", rpm:"libQt53DQuickExtras-devel~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DAnimation5-debuginfo", rpm:"libQt53DAnimation5-debuginfo~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuickScene2D-devel", rpm:"libQt53DQuickScene2D-devel~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DAnimation5", rpm:"libQt53DAnimation5~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DLogic5-debuginfo", rpm:"libQt53DLogic5-debuginfo~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DCore5", rpm:"libQt53DCore5~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuick-devel", rpm:"libQt53DQuick-devel~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuick5-debuginfo", rpm:"libQt53DQuick5-debuginfo~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuickAnimation5-debuginfo", rpm:"libQt53DQuickAnimation5-debuginfo~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuickInput-devel", rpm:"libQt53DQuickInput-devel~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuickRender5-debuginfo", rpm:"libQt53DQuickRender5-debuginfo~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DInput5", rpm:"libQt53DInput5~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuickAnimation-devel", rpm:"libQt53DQuickAnimation-devel~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DLogic5", rpm:"libQt53DLogic5~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuickInput5", rpm:"libQt53DQuickInput5~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DCore5-debuginfo", rpm:"libQt53DCore5-debuginfo~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DExtras5-debuginfo", rpm:"libQt53DExtras5-debuginfo~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuick5", rpm:"libQt53DQuick5~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qt3d-tools", rpm:"libqt5-qt3d-tools~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuickExtras5", rpm:"libQt53DQuickExtras5~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qt3d-examples", rpm:"libqt5-qt3d-examples~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qt3d-imports-debuginfo", rpm:"libqt5-qt3d-imports-debuginfo~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DRender-devel", rpm:"libQt53DRender-devel~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuickExtras5-debuginfo", rpm:"libQt53DQuickExtras5-debuginfo~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DExtras5", rpm:"libQt53DExtras5~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuickInput5-debuginfo", rpm:"libQt53DQuickInput5-debuginfo~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qt3d-debugsource", rpm:"libqt5-qt3d-debugsource~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DLogic-devel", rpm:"libQt53DLogic-devel~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DRender5-debuginfo", rpm:"libQt53DRender5-debuginfo~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qt3d-examples-debuginfo", rpm:"libqt5-qt3d-examples-debuginfo~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DQuickScene2D5", rpm:"libQt53DQuickScene2D5~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt53DRender5", rpm:"libQt53DRender5~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qt3d-private-headers-devel", rpm:"libqt5-qt3d-private-headers-devel~5.15.2+kde39~150400.3.3.1", rls:"openSUSELeap15.4"))) {
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
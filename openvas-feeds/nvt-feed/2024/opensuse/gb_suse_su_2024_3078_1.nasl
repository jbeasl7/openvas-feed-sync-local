# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856410");
  script_cve_id("CVE-2024-40724");
  script_tag(name:"creation_date", value:"2024-09-04 04:00:32 +0000 (Wed, 04 Sep 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-07 20:15:57 +0000 (Wed, 07 Aug 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:3078-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3078-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243078-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228199");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-September/036724.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libqt5-qtquick3d' package(s) announced via the SUSE-SU-2024:3078-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libqt5-qtquick3d fixes the following issues:

- CVE-2024-40724: Fixed heap-based buffer overflow in the PLY importer class in assimp (bsc#1228199)

Other fixes:
- Fix progressive anti-aliasing, which doesn't work if any object in the scene used a PrincipledMaterial
- Skip processing unknown uniforms, such as those that are vendor specific:");

  script_tag(name:"affected", value:"'libqt5-qtquick3d' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"libQt5Quick3D5", rpm:"libQt5Quick3D5~5.15.8+kde1~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Quick3DAssetImport5", rpm:"libQt5Quick3DAssetImport5~5.15.8+kde1~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtquick3d-devel", rpm:"libqt5-qtquick3d-devel~5.15.8+kde1~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtquick3d-examples", rpm:"libqt5-qtquick3d-examples~5.15.8+kde1~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtquick3d-imports", rpm:"libqt5-qtquick3d-imports~5.15.8+kde1~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtquick3d-private-headers-devel", rpm:"libqt5-qtquick3d-private-headers-devel~5.15.8+kde1~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtquick3d-tools", rpm:"libqt5-qtquick3d-tools~5.15.8+kde1~150500.3.3.1", rls:"openSUSELeap15.5"))) {
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

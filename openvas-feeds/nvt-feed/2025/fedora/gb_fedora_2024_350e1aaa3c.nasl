# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.3501011979797399");
  script_cve_id("CVE-2024-25580");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-350e1aaa3c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-350e1aaa3c");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-350e1aaa3c");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264426");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-qt6-qt3d, mingw-qt6-qt5compat, mingw-qt6-qtactiveqt, mingw-qt6-qtbase, mingw-qt6-qtcharts, mingw-qt6-qtdeclarative, mingw-qt6-qtimageformats, mingw-qt6-qtlocation, mingw-qt6-qtmultimedia, mingw-qt6-qtpositioning, mingw-qt6-qtscxml, mingw-qt6-qtsensors, mingw-qt6-qtserialport, mingw-qt6-qtshadertools, mingw-qt6-qtsvg, mingw-qt6-qttools, mingw-qt6-qttranslations, mingw-qt6-qtwebchannel, mingw-qt6-qtwebsockets' package(s) announced via the FEDORA-2024-350e1aaa3c advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 6.6.2.");

  script_tag(name:"affected", value:"'mingw-qt6-qt3d, mingw-qt6-qt5compat, mingw-qt6-qtactiveqt, mingw-qt6-qtbase, mingw-qt6-qtcharts, mingw-qt6-qtdeclarative, mingw-qt6-qtimageformats, mingw-qt6-qtlocation, mingw-qt6-qtmultimedia, mingw-qt6-qtpositioning, mingw-qt6-qtscxml, mingw-qt6-qtsensors, mingw-qt6-qtserialport, mingw-qt6-qtshadertools, mingw-qt6-qtsvg, mingw-qt6-qttools, mingw-qt6-qttranslations, mingw-qt6-qtwebchannel, mingw-qt6-qtwebsockets' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt6-qt3d", rpm:"mingw-qt6-qt3d~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt6-qt5compat", rpm:"mingw-qt6-qt5compat~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt6-qtactiveqt", rpm:"mingw-qt6-qtactiveqt~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt6-qtbase", rpm:"mingw-qt6-qtbase~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt6-qtcharts", rpm:"mingw-qt6-qtcharts~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt6-qtdeclarative", rpm:"mingw-qt6-qtdeclarative~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt6-qtimageformats", rpm:"mingw-qt6-qtimageformats~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt6-qtlocation", rpm:"mingw-qt6-qtlocation~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt6-qtmultimedia", rpm:"mingw-qt6-qtmultimedia~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt6-qtpositioning", rpm:"mingw-qt6-qtpositioning~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt6-qtscxml", rpm:"mingw-qt6-qtscxml~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt6-qtsensors", rpm:"mingw-qt6-qtsensors~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt6-qtserialport", rpm:"mingw-qt6-qtserialport~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt6-qtshadertools", rpm:"mingw-qt6-qtshadertools~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt6-qtsvg", rpm:"mingw-qt6-qtsvg~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt6-qttools", rpm:"mingw-qt6-qttools~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt6-qttranslations", rpm:"mingw-qt6-qttranslations~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt6-qtwebchannel", rpm:"mingw-qt6-qtwebchannel~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt6-qtwebsockets", rpm:"mingw-qt6-qtwebsockets~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qt3d", rpm:"mingw32-qt6-qt3d~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qt3d-debuginfo", rpm:"mingw32-qt6-qt3d-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qt5compat", rpm:"mingw32-qt6-qt5compat~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qt5compat-debuginfo", rpm:"mingw32-qt6-qt5compat-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtactiveqt", rpm:"mingw32-qt6-qtactiveqt~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtactiveqt-debuginfo", rpm:"mingw32-qt6-qtactiveqt-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtbase", rpm:"mingw32-qt6-qtbase~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtbase-debuginfo", rpm:"mingw32-qt6-qtbase-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtcharts", rpm:"mingw32-qt6-qtcharts~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtcharts-debuginfo", rpm:"mingw32-qt6-qtcharts-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtdeclarative", rpm:"mingw32-qt6-qtdeclarative~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtdeclarative-debuginfo", rpm:"mingw32-qt6-qtdeclarative-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtimageformats", rpm:"mingw32-qt6-qtimageformats~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtimageformats-debuginfo", rpm:"mingw32-qt6-qtimageformats-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtlocation", rpm:"mingw32-qt6-qtlocation~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtlocation-debuginfo", rpm:"mingw32-qt6-qtlocation-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtmultimedia", rpm:"mingw32-qt6-qtmultimedia~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtmultimedia-debuginfo", rpm:"mingw32-qt6-qtmultimedia-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtpositioning", rpm:"mingw32-qt6-qtpositioning~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtpositioning-debuginfo", rpm:"mingw32-qt6-qtpositioning-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtscxml", rpm:"mingw32-qt6-qtscxml~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtscxml-debuginfo", rpm:"mingw32-qt6-qtscxml-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtsensors", rpm:"mingw32-qt6-qtsensors~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtsensors-debuginfo", rpm:"mingw32-qt6-qtsensors-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtserialport", rpm:"mingw32-qt6-qtserialport~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtserialport-debuginfo", rpm:"mingw32-qt6-qtserialport-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtshadertools", rpm:"mingw32-qt6-qtshadertools~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtshadertools-debuginfo", rpm:"mingw32-qt6-qtshadertools-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtsvg", rpm:"mingw32-qt6-qtsvg~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtsvg-debuginfo", rpm:"mingw32-qt6-qtsvg-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qttools", rpm:"mingw32-qt6-qttools~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qttools-debuginfo", rpm:"mingw32-qt6-qttools-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qttranslations", rpm:"mingw32-qt6-qttranslations~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtwebchannel", rpm:"mingw32-qt6-qtwebchannel~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtwebchannel-debuginfo", rpm:"mingw32-qt6-qtwebchannel-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtwebsockets", rpm:"mingw32-qt6-qtwebsockets~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtwebsockets-debuginfo", rpm:"mingw32-qt6-qtwebsockets-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qt3d", rpm:"mingw64-qt6-qt3d~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qt3d-debuginfo", rpm:"mingw64-qt6-qt3d-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qt5compat", rpm:"mingw64-qt6-qt5compat~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qt5compat-debuginfo", rpm:"mingw64-qt6-qt5compat-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtactiveqt", rpm:"mingw64-qt6-qtactiveqt~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtactiveqt-debuginfo", rpm:"mingw64-qt6-qtactiveqt-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtbase", rpm:"mingw64-qt6-qtbase~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtbase-debuginfo", rpm:"mingw64-qt6-qtbase-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtcharts", rpm:"mingw64-qt6-qtcharts~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtcharts-debuginfo", rpm:"mingw64-qt6-qtcharts-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtdeclarative", rpm:"mingw64-qt6-qtdeclarative~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtdeclarative-debuginfo", rpm:"mingw64-qt6-qtdeclarative-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtimageformats", rpm:"mingw64-qt6-qtimageformats~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtimageformats-debuginfo", rpm:"mingw64-qt6-qtimageformats-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtlocation", rpm:"mingw64-qt6-qtlocation~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtlocation-debuginfo", rpm:"mingw64-qt6-qtlocation-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtmultimedia", rpm:"mingw64-qt6-qtmultimedia~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtmultimedia-debuginfo", rpm:"mingw64-qt6-qtmultimedia-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtpositioning", rpm:"mingw64-qt6-qtpositioning~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtpositioning-debuginfo", rpm:"mingw64-qt6-qtpositioning-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtscxml", rpm:"mingw64-qt6-qtscxml~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtscxml-debuginfo", rpm:"mingw64-qt6-qtscxml-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtsensors", rpm:"mingw64-qt6-qtsensors~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtsensors-debuginfo", rpm:"mingw64-qt6-qtsensors-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtserialport", rpm:"mingw64-qt6-qtserialport~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtserialport-debuginfo", rpm:"mingw64-qt6-qtserialport-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtshadertools", rpm:"mingw64-qt6-qtshadertools~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtshadertools-debuginfo", rpm:"mingw64-qt6-qtshadertools-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtsvg", rpm:"mingw64-qt6-qtsvg~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtsvg-debuginfo", rpm:"mingw64-qt6-qtsvg-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qttools", rpm:"mingw64-qt6-qttools~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qttools-debuginfo", rpm:"mingw64-qt6-qttools-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qttranslations", rpm:"mingw64-qt6-qttranslations~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtwebchannel", rpm:"mingw64-qt6-qtwebchannel~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtwebchannel-debuginfo", rpm:"mingw64-qt6-qtwebchannel-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtwebsockets", rpm:"mingw64-qt6-qtwebsockets~6.6.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtwebsockets-debuginfo", rpm:"mingw64-qt6-qtwebsockets-debuginfo~6.6.2~1.fc41", rls:"FC41"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.029999100410097101100");
  script_cve_id("CVE-2024-25580");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-02ccd4daed)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-02ccd4daed");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-02ccd4daed");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264425");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-qt5-qt3d, mingw-qt5-qtactiveqt, mingw-qt5-qtbase, mingw-qt5-qtcharts, mingw-qt5-qtdeclarative, mingw-qt5-qtgraphicaleffects, mingw-qt5-qtimageformats, mingw-qt5-qtlocation, mingw-qt5-qtmultimedia, mingw-qt5-qtquickcontrols, mingw-qt5-qtquickcontrols2, mingw-qt5-qtscript, mingw-qt5-qtsensors, mingw-qt5-qtserialport, mingw-qt5-qtsvg, mingw-qt5-qttools, mingw-qt5-qttranslations, mingw-qt5-qtwebchannel, mingw-qt5-qtwebsockets, mingw-qt5-qtwinextras, mingw-qt5-qtxmlpatterns' package(s) announced via the FEDORA-2024-02ccd4daed advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to qt-5.15.12.");

  script_tag(name:"affected", value:"'mingw-qt5-qt3d, mingw-qt5-qtactiveqt, mingw-qt5-qtbase, mingw-qt5-qtcharts, mingw-qt5-qtdeclarative, mingw-qt5-qtgraphicaleffects, mingw-qt5-qtimageformats, mingw-qt5-qtlocation, mingw-qt5-qtmultimedia, mingw-qt5-qtquickcontrols, mingw-qt5-qtquickcontrols2, mingw-qt5-qtscript, mingw-qt5-qtsensors, mingw-qt5-qtserialport, mingw-qt5-qtsvg, mingw-qt5-qttools, mingw-qt5-qttranslations, mingw-qt5-qtwebchannel, mingw-qt5-qtwebsockets, mingw-qt5-qtwinextras, mingw-qt5-qtxmlpatterns' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qt3d", rpm:"mingw-qt5-qt3d~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qt3d-debuginfo", rpm:"mingw-qt5-qt3d-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qtactiveqt", rpm:"mingw-qt5-qtactiveqt~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qtbase", rpm:"mingw-qt5-qtbase~5.15.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qtbase-debuginfo", rpm:"mingw-qt5-qtbase-debuginfo~5.15.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qtcharts", rpm:"mingw-qt5-qtcharts~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qtdeclarative", rpm:"mingw-qt5-qtdeclarative~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qtdeclarative-debuginfo", rpm:"mingw-qt5-qtdeclarative-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qtgraphicaleffects", rpm:"mingw-qt5-qtgraphicaleffects~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qtimageformats", rpm:"mingw-qt5-qtimageformats~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qtlocation", rpm:"mingw-qt5-qtlocation~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qtmultimedia", rpm:"mingw-qt5-qtmultimedia~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qtquickcontrols", rpm:"mingw-qt5-qtquickcontrols~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qtquickcontrols2", rpm:"mingw-qt5-qtquickcontrols2~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qtscript", rpm:"mingw-qt5-qtscript~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qtsensors", rpm:"mingw-qt5-qtsensors~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qtserialport", rpm:"mingw-qt5-qtserialport~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qtsvg", rpm:"mingw-qt5-qtsvg~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qttools", rpm:"mingw-qt5-qttools~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qttools-debuginfo", rpm:"mingw-qt5-qttools-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qttranslations", rpm:"mingw-qt5-qttranslations~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qtwebchannel", rpm:"mingw-qt5-qtwebchannel~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qtwebsockets", rpm:"mingw-qt5-qtwebsockets~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qtwinextras", rpm:"mingw-qt5-qtwinextras~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qtxmlpatterns", rpm:"mingw-qt5-qtxmlpatterns~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qmake", rpm:"mingw32-qt5-qmake~5.15.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qmldevtools", rpm:"mingw32-qt5-qmldevtools~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qmldevtools-devel", rpm:"mingw32-qt5-qmldevtools-devel~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qt3d", rpm:"mingw32-qt5-qt3d~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qt3d-debuginfo", rpm:"mingw32-qt5-qt3d-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qt3d-tools", rpm:"mingw32-qt5-qt3d-tools~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtactiveqt", rpm:"mingw32-qt5-qtactiveqt~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtactiveqt-debuginfo", rpm:"mingw32-qt5-qtactiveqt-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtbase", rpm:"mingw32-qt5-qtbase~5.15.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtbase-debuginfo", rpm:"mingw32-qt5-qtbase-debuginfo~5.15.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtbase-devel", rpm:"mingw32-qt5-qtbase-devel~5.15.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtbase-static", rpm:"mingw32-qt5-qtbase-static~5.15.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtcharts", rpm:"mingw32-qt5-qtcharts~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtcharts-debuginfo", rpm:"mingw32-qt5-qtcharts-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtdeclarative", rpm:"mingw32-qt5-qtdeclarative~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtdeclarative-debuginfo", rpm:"mingw32-qt5-qtdeclarative-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtdeclarative-static", rpm:"mingw32-qt5-qtdeclarative-static~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtgraphicaleffects", rpm:"mingw32-qt5-qtgraphicaleffects~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtgraphicaleffects-debuginfo", rpm:"mingw32-qt5-qtgraphicaleffects-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtimageformats", rpm:"mingw32-qt5-qtimageformats~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtimageformats-debuginfo", rpm:"mingw32-qt5-qtimageformats-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtlocation", rpm:"mingw32-qt5-qtlocation~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtlocation-debuginfo", rpm:"mingw32-qt5-qtlocation-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtmultimedia", rpm:"mingw32-qt5-qtmultimedia~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtmultimedia-debuginfo", rpm:"mingw32-qt5-qtmultimedia-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtquickcontrols", rpm:"mingw32-qt5-qtquickcontrols~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtquickcontrols-debuginfo", rpm:"mingw32-qt5-qtquickcontrols-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtquickcontrols-static", rpm:"mingw32-qt5-qtquickcontrols-static~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtquickcontrols2", rpm:"mingw32-qt5-qtquickcontrols2~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtquickcontrols2-debuginfo", rpm:"mingw32-qt5-qtquickcontrols2-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtquickcontrols2-static", rpm:"mingw32-qt5-qtquickcontrols2-static~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtscript", rpm:"mingw32-qt5-qtscript~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtscript-debuginfo", rpm:"mingw32-qt5-qtscript-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtsensors", rpm:"mingw32-qt5-qtsensors~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtsensors-debuginfo", rpm:"mingw32-qt5-qtsensors-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtserialport", rpm:"mingw32-qt5-qtserialport~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtserialport-debuginfo", rpm:"mingw32-qt5-qtserialport-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtsvg", rpm:"mingw32-qt5-qtsvg~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtsvg-debuginfo", rpm:"mingw32-qt5-qtsvg-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qttools", rpm:"mingw32-qt5-qttools~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qttools-debuginfo", rpm:"mingw32-qt5-qttools-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qttools-tools", rpm:"mingw32-qt5-qttools-tools~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qttranslations", rpm:"mingw32-qt5-qttranslations~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtwebchannel", rpm:"mingw32-qt5-qtwebchannel~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtwebchannel-debuginfo", rpm:"mingw32-qt5-qtwebchannel-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtwebsockets", rpm:"mingw32-qt5-qtwebsockets~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtwebsockets-debuginfo", rpm:"mingw32-qt5-qtwebsockets-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtwinextras", rpm:"mingw32-qt5-qtwinextras~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtwinextras-debuginfo", rpm:"mingw32-qt5-qtwinextras-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtxmlpatterns", rpm:"mingw32-qt5-qtxmlpatterns~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt5-qtxmlpatterns-debuginfo", rpm:"mingw32-qt5-qtxmlpatterns-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qmake", rpm:"mingw64-qt5-qmake~5.15.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qmldevtools", rpm:"mingw64-qt5-qmldevtools~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qmldevtools-devel", rpm:"mingw64-qt5-qmldevtools-devel~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qt3d", rpm:"mingw64-qt5-qt3d~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qt3d-debuginfo", rpm:"mingw64-qt5-qt3d-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qt3d-tools", rpm:"mingw64-qt5-qt3d-tools~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtactiveqt", rpm:"mingw64-qt5-qtactiveqt~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtactiveqt-debuginfo", rpm:"mingw64-qt5-qtactiveqt-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtbase", rpm:"mingw64-qt5-qtbase~5.15.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtbase-debuginfo", rpm:"mingw64-qt5-qtbase-debuginfo~5.15.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtbase-devel", rpm:"mingw64-qt5-qtbase-devel~5.15.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtbase-static", rpm:"mingw64-qt5-qtbase-static~5.15.12~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtcharts", rpm:"mingw64-qt5-qtcharts~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtcharts-debuginfo", rpm:"mingw64-qt5-qtcharts-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtdeclarative", rpm:"mingw64-qt5-qtdeclarative~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtdeclarative-debuginfo", rpm:"mingw64-qt5-qtdeclarative-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtdeclarative-static", rpm:"mingw64-qt5-qtdeclarative-static~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtgraphicaleffects", rpm:"mingw64-qt5-qtgraphicaleffects~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtgraphicaleffects-debuginfo", rpm:"mingw64-qt5-qtgraphicaleffects-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtimageformats", rpm:"mingw64-qt5-qtimageformats~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtimageformats-debuginfo", rpm:"mingw64-qt5-qtimageformats-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtlocation", rpm:"mingw64-qt5-qtlocation~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtlocation-debuginfo", rpm:"mingw64-qt5-qtlocation-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtmultimedia", rpm:"mingw64-qt5-qtmultimedia~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtmultimedia-debuginfo", rpm:"mingw64-qt5-qtmultimedia-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtquickcontrols", rpm:"mingw64-qt5-qtquickcontrols~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtquickcontrols-debuginfo", rpm:"mingw64-qt5-qtquickcontrols-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtquickcontrols-static", rpm:"mingw64-qt5-qtquickcontrols-static~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtquickcontrols2", rpm:"mingw64-qt5-qtquickcontrols2~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtquickcontrols2-debuginfo", rpm:"mingw64-qt5-qtquickcontrols2-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtquickcontrols2-static", rpm:"mingw64-qt5-qtquickcontrols2-static~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtscript", rpm:"mingw64-qt5-qtscript~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtscript-debuginfo", rpm:"mingw64-qt5-qtscript-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtsensors", rpm:"mingw64-qt5-qtsensors~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtsensors-debuginfo", rpm:"mingw64-qt5-qtsensors-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtserialport", rpm:"mingw64-qt5-qtserialport~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtserialport-debuginfo", rpm:"mingw64-qt5-qtserialport-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtsvg", rpm:"mingw64-qt5-qtsvg~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtsvg-debuginfo", rpm:"mingw64-qt5-qtsvg-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qttools", rpm:"mingw64-qt5-qttools~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qttools-debuginfo", rpm:"mingw64-qt5-qttools-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qttools-tools", rpm:"mingw64-qt5-qttools-tools~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qttranslations", rpm:"mingw64-qt5-qttranslations~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtwebchannel", rpm:"mingw64-qt5-qtwebchannel~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtwebchannel-debuginfo", rpm:"mingw64-qt5-qtwebchannel-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtwebsockets", rpm:"mingw64-qt5-qtwebsockets~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtwebsockets-debuginfo", rpm:"mingw64-qt5-qtwebsockets-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtwinextras", rpm:"mingw64-qt5-qtwinextras~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtwinextras-debuginfo", rpm:"mingw64-qt5-qtwinextras-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtxmlpatterns", rpm:"mingw64-qt5-qtxmlpatterns~5.15.12~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt5-qtxmlpatterns-debuginfo", rpm:"mingw64-qt5-qtxmlpatterns-debuginfo~5.15.12~1.fc41", rls:"FC41"))) {
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

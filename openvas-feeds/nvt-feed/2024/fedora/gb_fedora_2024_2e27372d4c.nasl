# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887013");
  script_cve_id("CVE-2024-36048");
  script_tag(name:"creation_date", value:"2024-06-07 06:35:20 +0000 (Fri, 07 Jun 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-2e27372d4c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-2e27372d4c");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-2e27372d4c");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282866");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282867");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282869");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'deepin-qt5integration, deepin-qt5platform-plugins, dwayland, fcitx5-qt, fcitx-qt5, gammaray, kddockwidgets, keepassxc, kf5-akonadi-server, kf5-frameworkintegration, kf5-kwayland, plasma-integration, python-qt5, qadwaitadecorations, qgnomeplatform, qt5, qt5-qt3d, qt5-qtbase, qt5-qtcharts, qt5-qtconnectivity, qt5-qtdatavis3d, qt5-qtdeclarative, qt5-qtdoc, qt5-qtgamepad, qt5-qtgraphicaleffects, qt5-qtimageformats, qt5-qtlocation, qt5-qtmultimedia, qt5-qtnetworkauth, qt5-qtquickcontrols, qt5-qtquickcontrols2, qt5-qtremoteobjects, qt5-qtscript, qt5-qtscxml, qt5-qtsensors, qt5-qtserialbus, qt5-qtserialport, qt5-qtspeech, qt5-qtsvg, qt5-qttools, qt5-qttranslations, qt5-qtvirtualkeyboard, qt5-qtwayland, qt5-qtwebchannel, qt5-qtwebengine, qt5-qtwebkit, qt5-qtwebsockets, qt5-qtwebview, qt5-qtx11extras, qt5-qtxmlpatterns, qt5ct' package(s) announced via the FEDORA-2024-2e27372d4c advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Qt 5.15.14 bugfix update.

----

Fix CVE-2024-36048");

  script_tag(name:"affected", value:"'deepin-qt5integration, deepin-qt5platform-plugins, dwayland, fcitx5-qt, fcitx-qt5, gammaray, kddockwidgets, keepassxc, kf5-akonadi-server, kf5-frameworkintegration, kf5-kwayland, plasma-integration, python-qt5, qadwaitadecorations, qgnomeplatform, qt5, qt5-qt3d, qt5-qtbase, qt5-qtcharts, qt5-qtconnectivity, qt5-qtdatavis3d, qt5-qtdeclarative, qt5-qtdoc, qt5-qtgamepad, qt5-qtgraphicaleffects, qt5-qtimageformats, qt5-qtlocation, qt5-qtmultimedia, qt5-qtnetworkauth, qt5-qtquickcontrols, qt5-qtquickcontrols2, qt5-qtremoteobjects, qt5-qtscript, qt5-qtscxml, qt5-qtsensors, qt5-qtserialbus, qt5-qtserialport, qt5-qtspeech, qt5-qtsvg, qt5-qttools, qt5-qttranslations, qt5-qtvirtualkeyboard, qt5-qtwayland, qt5-qtwebchannel, qt5-qtwebengine, qt5-qtwebkit, qt5-qtwebsockets, qt5-qtwebview, qt5-qtx11extras, qt5-qtxmlpatterns, qt5ct' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"deepin-qt5integration", rpm:"deepin-qt5integration~5.6.11~7.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"deepin-qt5integration-debuginfo", rpm:"deepin-qt5integration-debuginfo~5.6.11~7.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"deepin-qt5integration-debugsource", rpm:"deepin-qt5integration-debugsource~5.6.11~7.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"deepin-qt5platform-plugins", rpm:"deepin-qt5platform-plugins~5.6.12~7.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"deepin-qt5platform-plugins-debuginfo", rpm:"deepin-qt5platform-plugins-debuginfo~5.6.12~7.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"deepin-qt5platform-plugins-debugsource", rpm:"deepin-qt5platform-plugins-debugsource~5.6.12~7.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dwayland", rpm:"dwayland~5.25.0~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dwayland-debuginfo", rpm:"dwayland-debuginfo~5.25.0~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dwayland-debugsource", rpm:"dwayland-debugsource~5.25.0~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dwayland-devel", rpm:"dwayland-devel~5.25.0~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx-qt5", rpm:"fcitx-qt5~1.2.6~21.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx-qt5-debuginfo", rpm:"fcitx-qt5-debuginfo~1.2.6~21.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx-qt5-debugsource", rpm:"fcitx-qt5-debugsource~1.2.6~21.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx-qt5-devel", rpm:"fcitx-qt5-devel~1.2.6~21.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt", rpm:"fcitx5-qt~5.1.6~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-debuginfo", rpm:"fcitx5-qt-debuginfo~5.1.6~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-debugsource", rpm:"fcitx5-qt-debugsource~5.1.6~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-devel", rpm:"fcitx5-qt-devel~5.1.6~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-libfcitx5qt5widgets", rpm:"fcitx5-qt-libfcitx5qt5widgets~5.1.6~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-libfcitx5qt5widgets-debuginfo", rpm:"fcitx5-qt-libfcitx5qt5widgets-debuginfo~5.1.6~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-libfcitx5qt6widgets", rpm:"fcitx5-qt-libfcitx5qt6widgets~5.1.6~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-libfcitx5qt6widgets-debuginfo", rpm:"fcitx5-qt-libfcitx5qt6widgets-debuginfo~5.1.6~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-libfcitx5qtdbus", rpm:"fcitx5-qt-libfcitx5qtdbus~5.1.6~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-libfcitx5qtdbus-debuginfo", rpm:"fcitx5-qt-libfcitx5qtdbus-debuginfo~5.1.6~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-qt5gui", rpm:"fcitx5-qt-qt5gui~5.1.6~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-qt5gui-debuginfo", rpm:"fcitx5-qt-qt5gui-debuginfo~5.1.6~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-qt6gui", rpm:"fcitx5-qt-qt6gui~5.1.6~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-qt6gui-debuginfo", rpm:"fcitx5-qt-qt6gui-debuginfo~5.1.6~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt5", rpm:"fcitx5-qt5~5.1.6~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt5-debuginfo", rpm:"fcitx5-qt5-debuginfo~5.1.6~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt6", rpm:"fcitx5-qt6~5.1.6~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt6-debuginfo", rpm:"fcitx5-qt6-debuginfo~5.1.6~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gammaray", rpm:"gammaray~3.0.0~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gammaray-debuginfo", rpm:"gammaray-debuginfo~3.0.0~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gammaray-debugsource", rpm:"gammaray-debugsource~3.0.0~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gammaray-devel", rpm:"gammaray-devel~3.0.0~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gammaray-doc", rpm:"gammaray-doc~3.0.0~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gammaray-probe-qt5", rpm:"gammaray-probe-qt5~3.0.0~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gammaray-probe-qt5-debuginfo", rpm:"gammaray-probe-qt5-debuginfo~3.0.0~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gammaray-probe-qt5-devel", rpm:"gammaray-probe-qt5-devel~3.0.0~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gammaray-probe-qt6", rpm:"gammaray-probe-qt6~3.0.0~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gammaray-probe-qt6-debuginfo", rpm:"gammaray-probe-qt6-debuginfo~3.0.0~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gammaray-probe-qt6-devel", rpm:"gammaray-probe-qt6-devel~3.0.0~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gammaray-probe-qt6-devel-debuginfo", rpm:"gammaray-probe-qt6-devel-debuginfo~3.0.0~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kddockwidgets", rpm:"kddockwidgets~1.7.0~10.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kddockwidgets-debuginfo", rpm:"kddockwidgets-debuginfo~1.7.0~10.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kddockwidgets-debugsource", rpm:"kddockwidgets-debugsource~1.7.0~10.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kddockwidgets-devel", rpm:"kddockwidgets-devel~1.7.0~10.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kddockwidgets-qt6", rpm:"kddockwidgets-qt6~1.7.0~10.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kddockwidgets-qt6-debuginfo", rpm:"kddockwidgets-qt6-debuginfo~1.7.0~10.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kddockwidgets-qt6-devel", rpm:"kddockwidgets-qt6-devel~1.7.0~10.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keepassxc", rpm:"keepassxc~2.7.8~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keepassxc-debuginfo", rpm:"keepassxc-debuginfo~2.7.8~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keepassxc-debugsource", rpm:"keepassxc-debugsource~2.7.8~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf5-akonadi-server", rpm:"kf5-akonadi-server~23.08.5~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf5-akonadi-server-debuginfo", rpm:"kf5-akonadi-server-debuginfo~23.08.5~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf5-akonadi-server-debugsource", rpm:"kf5-akonadi-server-debugsource~23.08.5~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf5-akonadi-server-devel", rpm:"kf5-akonadi-server-devel~23.08.5~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf5-akonadi-server-devel-debuginfo", rpm:"kf5-akonadi-server-devel-debuginfo~23.08.5~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf5-akonadi-server-libs", rpm:"kf5-akonadi-server-libs~23.08.5~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf5-akonadi-server-libs-debuginfo", rpm:"kf5-akonadi-server-libs-debuginfo~23.08.5~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf5-akonadi-server-mysql", rpm:"kf5-akonadi-server-mysql~23.08.5~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf5-frameworkintegration", rpm:"kf5-frameworkintegration~5.115.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf5-frameworkintegration-debuginfo", rpm:"kf5-frameworkintegration-debuginfo~5.115.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf5-frameworkintegration-debugsource", rpm:"kf5-frameworkintegration-debugsource~5.115.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf5-frameworkintegration-devel", rpm:"kf5-frameworkintegration-devel~5.115.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf5-frameworkintegration-libs", rpm:"kf5-frameworkintegration-libs~5.115.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf5-frameworkintegration-libs-debuginfo", rpm:"kf5-frameworkintegration-libs-debuginfo~5.115.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf5-kwayland", rpm:"kf5-kwayland~5.115.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf5-kwayland-debuginfo", rpm:"kf5-kwayland-debuginfo~5.115.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf5-kwayland-debugsource", rpm:"kf5-kwayland-debugsource~5.115.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf5-kwayland-devel", rpm:"kf5-kwayland-devel~5.115.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-integration", rpm:"plasma-integration~6.0.5~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-integration-debuginfo", rpm:"plasma-integration-debuginfo~6.0.5~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-integration-debugsource", rpm:"plasma-integration-debugsource~6.0.5~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-integration-qt5", rpm:"plasma-integration-qt5~6.0.5~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma-integration-qt5-debuginfo", rpm:"plasma-integration-qt5-debuginfo~6.0.5~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-qt5", rpm:"python-qt5~5.15.10~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-qt5-debuginfo", rpm:"python-qt5-debuginfo~5.15.10~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-qt5-debugsource", rpm:"python-qt5-debugsource~5.15.10~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-qt5-doc", rpm:"python-qt5-doc~5.15.10~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-qt5-rpm-macros", rpm:"python-qt5-rpm-macros~5.15.10~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-qt5", rpm:"python3-qt5~5.15.10~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-qt5-base", rpm:"python3-qt5-base~5.15.10~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-qt5-base-debuginfo", rpm:"python3-qt5-base-debuginfo~5.15.10~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-qt5-debuginfo", rpm:"python3-qt5-debuginfo~5.15.10~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-qt5-devel", rpm:"python3-qt5-devel~5.15.10~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-qt5-webkit", rpm:"python3-qt5-webkit~5.15.10~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-qt5-webkit-debuginfo", rpm:"python3-qt5-webkit-debuginfo~5.15.10~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qadwaitadecorations", rpm:"qadwaitadecorations~0.1.5~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qadwaitadecorations-debuginfo", rpm:"qadwaitadecorations-debuginfo~0.1.5~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qadwaitadecorations-debugsource", rpm:"qadwaitadecorations-debugsource~0.1.5~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qadwaitadecorations-qt5", rpm:"qadwaitadecorations-qt5~0.1.5~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qadwaitadecorations-qt5-debuginfo", rpm:"qadwaitadecorations-qt5-debuginfo~0.1.5~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qadwaitadecorations-qt6", rpm:"qadwaitadecorations-qt6~0.1.5~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qadwaitadecorations-qt6-debuginfo", rpm:"qadwaitadecorations-qt6-debuginfo~0.1.5~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qgnomeplatform", rpm:"qgnomeplatform~0.9.2~15.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qgnomeplatform-common", rpm:"qgnomeplatform-common~0.9.2~15.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qgnomeplatform-debuginfo", rpm:"qgnomeplatform-debuginfo~0.9.2~15.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qgnomeplatform-debugsource", rpm:"qgnomeplatform-debugsource~0.9.2~15.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qgnomeplatform-qt5", rpm:"qgnomeplatform-qt5~0.9.2~15.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qgnomeplatform-qt5-debuginfo", rpm:"qgnomeplatform-qt5-debuginfo~0.9.2~15.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qgnomeplatform-qt6", rpm:"qgnomeplatform-qt6~0.9.2~15.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qgnomeplatform-qt6-debuginfo", rpm:"qgnomeplatform-qt6-debuginfo~0.9.2~15.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5", rpm:"qt5~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-assistant", rpm:"qt5-assistant~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-assistant-debuginfo", rpm:"qt5-assistant-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-designer", rpm:"qt5-designer~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-designer-debuginfo", rpm:"qt5-designer-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-doctools", rpm:"qt5-doctools~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-doctools-debuginfo", rpm:"qt5-doctools-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-linguist", rpm:"qt5-linguist~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-linguist-debuginfo", rpm:"qt5-linguist-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qdbusviewer", rpm:"qt5-qdbusviewer~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qdbusviewer-debuginfo", rpm:"qt5-qdbusviewer-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qt3d", rpm:"qt5-qt3d~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qt3d-debuginfo", rpm:"qt5-qt3d-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qt3d-debugsource", rpm:"qt5-qt3d-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qt3d-devel", rpm:"qt5-qt3d-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qt3d-devel-debuginfo", rpm:"qt5-qt3d-devel-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qt3d-examples", rpm:"qt5-qt3d-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qt3d-examples-debuginfo", rpm:"qt5-qt3d-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase", rpm:"qt5-qtbase~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-common", rpm:"qt5-qtbase-common~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-debuginfo", rpm:"qt5-qtbase-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-debugsource", rpm:"qt5-qtbase-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-devel", rpm:"qt5-qtbase-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-devel-debuginfo", rpm:"qt5-qtbase-devel-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-examples", rpm:"qt5-qtbase-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-examples-debuginfo", rpm:"qt5-qtbase-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-gui", rpm:"qt5-qtbase-gui~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-gui-debuginfo", rpm:"qt5-qtbase-gui-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-ibase", rpm:"qt5-qtbase-ibase~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-ibase-debuginfo", rpm:"qt5-qtbase-ibase-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-mysql", rpm:"qt5-qtbase-mysql~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-mysql-debuginfo", rpm:"qt5-qtbase-mysql-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-odbc", rpm:"qt5-qtbase-odbc~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-odbc-debuginfo", rpm:"qt5-qtbase-odbc-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-postgresql", rpm:"qt5-qtbase-postgresql~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-postgresql-debuginfo", rpm:"qt5-qtbase-postgresql-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-private-devel", rpm:"qt5-qtbase-private-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-static", rpm:"qt5-qtbase-static~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-tds", rpm:"qt5-qtbase-tds~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-tds-debuginfo", rpm:"qt5-qtbase-tds-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtcharts", rpm:"qt5-qtcharts~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtcharts-debuginfo", rpm:"qt5-qtcharts-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtcharts-debugsource", rpm:"qt5-qtcharts-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtcharts-devel", rpm:"qt5-qtcharts-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtcharts-examples", rpm:"qt5-qtcharts-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtcharts-examples-debuginfo", rpm:"qt5-qtcharts-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtconnectivity", rpm:"qt5-qtconnectivity~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtconnectivity-debuginfo", rpm:"qt5-qtconnectivity-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtconnectivity-debugsource", rpm:"qt5-qtconnectivity-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtconnectivity-devel", rpm:"qt5-qtconnectivity-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtconnectivity-examples", rpm:"qt5-qtconnectivity-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtconnectivity-examples-debuginfo", rpm:"qt5-qtconnectivity-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtdatavis3d", rpm:"qt5-qtdatavis3d~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtdatavis3d-debuginfo", rpm:"qt5-qtdatavis3d-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtdatavis3d-debugsource", rpm:"qt5-qtdatavis3d-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtdatavis3d-devel", rpm:"qt5-qtdatavis3d-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtdatavis3d-examples", rpm:"qt5-qtdatavis3d-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtdatavis3d-examples-debuginfo", rpm:"qt5-qtdatavis3d-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtdeclarative", rpm:"qt5-qtdeclarative~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtdeclarative-debuginfo", rpm:"qt5-qtdeclarative-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtdeclarative-debugsource", rpm:"qt5-qtdeclarative-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtdeclarative-devel", rpm:"qt5-qtdeclarative-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtdeclarative-devel-debuginfo", rpm:"qt5-qtdeclarative-devel-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtdeclarative-examples", rpm:"qt5-qtdeclarative-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtdeclarative-examples-debuginfo", rpm:"qt5-qtdeclarative-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtdeclarative-static", rpm:"qt5-qtdeclarative-static~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtdoc", rpm:"qt5-qtdoc~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtgamepad", rpm:"qt5-qtgamepad~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtgamepad-debuginfo", rpm:"qt5-qtgamepad-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtgamepad-debugsource", rpm:"qt5-qtgamepad-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtgamepad-devel", rpm:"qt5-qtgamepad-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtgamepad-examples", rpm:"qt5-qtgamepad-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtgamepad-examples-debuginfo", rpm:"qt5-qtgamepad-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtgraphicaleffects", rpm:"qt5-qtgraphicaleffects~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtgraphicaleffects-debuginfo", rpm:"qt5-qtgraphicaleffects-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtgraphicaleffects-debugsource", rpm:"qt5-qtgraphicaleffects-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtimageformats", rpm:"qt5-qtimageformats~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtimageformats-debuginfo", rpm:"qt5-qtimageformats-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtimageformats-debugsource", rpm:"qt5-qtimageformats-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtlocation", rpm:"qt5-qtlocation~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtlocation-debuginfo", rpm:"qt5-qtlocation-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtlocation-debugsource", rpm:"qt5-qtlocation-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtlocation-devel", rpm:"qt5-qtlocation-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtlocation-examples", rpm:"qt5-qtlocation-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtlocation-examples-debuginfo", rpm:"qt5-qtlocation-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtmultimedia", rpm:"qt5-qtmultimedia~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtmultimedia-debuginfo", rpm:"qt5-qtmultimedia-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtmultimedia-debugsource", rpm:"qt5-qtmultimedia-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtmultimedia-devel", rpm:"qt5-qtmultimedia-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtmultimedia-examples", rpm:"qt5-qtmultimedia-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtmultimedia-examples-debuginfo", rpm:"qt5-qtmultimedia-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtnetworkauth", rpm:"qt5-qtnetworkauth~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtnetworkauth-debuginfo", rpm:"qt5-qtnetworkauth-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtnetworkauth-debugsource", rpm:"qt5-qtnetworkauth-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtnetworkauth-devel", rpm:"qt5-qtnetworkauth-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtnetworkauth-examples", rpm:"qt5-qtnetworkauth-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtnetworkauth-examples-debuginfo", rpm:"qt5-qtnetworkauth-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtquickcontrols", rpm:"qt5-qtquickcontrols~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtquickcontrols-debuginfo", rpm:"qt5-qtquickcontrols-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtquickcontrols-debugsource", rpm:"qt5-qtquickcontrols-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtquickcontrols-examples", rpm:"qt5-qtquickcontrols-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtquickcontrols-examples-debuginfo", rpm:"qt5-qtquickcontrols-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtquickcontrols2", rpm:"qt5-qtquickcontrols2~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtquickcontrols2-debuginfo", rpm:"qt5-qtquickcontrols2-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtquickcontrols2-debugsource", rpm:"qt5-qtquickcontrols2-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtquickcontrols2-devel", rpm:"qt5-qtquickcontrols2-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtquickcontrols2-examples", rpm:"qt5-qtquickcontrols2-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtquickcontrols2-examples-debuginfo", rpm:"qt5-qtquickcontrols2-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtremoteobjects", rpm:"qt5-qtremoteobjects~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtremoteobjects-debuginfo", rpm:"qt5-qtremoteobjects-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtremoteobjects-debugsource", rpm:"qt5-qtremoteobjects-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtremoteobjects-devel", rpm:"qt5-qtremoteobjects-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtremoteobjects-examples", rpm:"qt5-qtremoteobjects-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtremoteobjects-examples-debuginfo", rpm:"qt5-qtremoteobjects-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtscript", rpm:"qt5-qtscript~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtscript-debuginfo", rpm:"qt5-qtscript-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtscript-debugsource", rpm:"qt5-qtscript-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtscript-devel", rpm:"qt5-qtscript-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtscript-examples", rpm:"qt5-qtscript-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtscript-examples-debuginfo", rpm:"qt5-qtscript-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtscxml", rpm:"qt5-qtscxml~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtscxml-debuginfo", rpm:"qt5-qtscxml-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtscxml-debugsource", rpm:"qt5-qtscxml-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtscxml-devel", rpm:"qt5-qtscxml-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtscxml-examples", rpm:"qt5-qtscxml-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtscxml-examples-debuginfo", rpm:"qt5-qtscxml-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtsensors", rpm:"qt5-qtsensors~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtsensors-debuginfo", rpm:"qt5-qtsensors-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtsensors-debugsource", rpm:"qt5-qtsensors-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtsensors-devel", rpm:"qt5-qtsensors-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtsensors-examples", rpm:"qt5-qtsensors-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtsensors-examples-debuginfo", rpm:"qt5-qtsensors-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtserialbus", rpm:"qt5-qtserialbus~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtserialbus-debuginfo", rpm:"qt5-qtserialbus-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtserialbus-debugsource", rpm:"qt5-qtserialbus-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtserialbus-devel", rpm:"qt5-qtserialbus-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtserialbus-examples", rpm:"qt5-qtserialbus-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtserialbus-examples-debuginfo", rpm:"qt5-qtserialbus-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtserialport", rpm:"qt5-qtserialport~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtserialport-debuginfo", rpm:"qt5-qtserialport-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtserialport-debugsource", rpm:"qt5-qtserialport-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtserialport-devel", rpm:"qt5-qtserialport-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtserialport-examples", rpm:"qt5-qtserialport-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtserialport-examples-debuginfo", rpm:"qt5-qtserialport-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtspeech", rpm:"qt5-qtspeech~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtspeech-debuginfo", rpm:"qt5-qtspeech-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtspeech-debugsource", rpm:"qt5-qtspeech-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtspeech-devel", rpm:"qt5-qtspeech-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtspeech-examples", rpm:"qt5-qtspeech-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtspeech-examples-debuginfo", rpm:"qt5-qtspeech-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtspeech-flite", rpm:"qt5-qtspeech-flite~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtspeech-flite-debuginfo", rpm:"qt5-qtspeech-flite-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtspeech-speechd", rpm:"qt5-qtspeech-speechd~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtspeech-speechd-debuginfo", rpm:"qt5-qtspeech-speechd-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtsvg", rpm:"qt5-qtsvg~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtsvg-debuginfo", rpm:"qt5-qtsvg-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtsvg-debugsource", rpm:"qt5-qtsvg-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtsvg-devel", rpm:"qt5-qtsvg-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtsvg-examples", rpm:"qt5-qtsvg-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtsvg-examples-debuginfo", rpm:"qt5-qtsvg-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qttools", rpm:"qt5-qttools~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qttools-common", rpm:"qt5-qttools-common~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qttools-debuginfo", rpm:"qt5-qttools-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qttools-debugsource", rpm:"qt5-qttools-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qttools-devel", rpm:"qt5-qttools-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qttools-devel-debuginfo", rpm:"qt5-qttools-devel-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qttools-examples", rpm:"qt5-qttools-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qttools-examples-debuginfo", rpm:"qt5-qttools-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qttools-libs-designer", rpm:"qt5-qttools-libs-designer~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qttools-libs-designer-debuginfo", rpm:"qt5-qttools-libs-designer-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qttools-libs-designercomponents", rpm:"qt5-qttools-libs-designercomponents~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qttools-libs-designercomponents-debuginfo", rpm:"qt5-qttools-libs-designercomponents-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qttools-libs-help", rpm:"qt5-qttools-libs-help~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qttools-libs-help-debuginfo", rpm:"qt5-qttools-libs-help-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qttools-static", rpm:"qt5-qttools-static~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qttranslations", rpm:"qt5-qttranslations~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtvirtualkeyboard", rpm:"qt5-qtvirtualkeyboard~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtvirtualkeyboard-debuginfo", rpm:"qt5-qtvirtualkeyboard-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtvirtualkeyboard-debugsource", rpm:"qt5-qtvirtualkeyboard-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtvirtualkeyboard-devel", rpm:"qt5-qtvirtualkeyboard-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtvirtualkeyboard-examples", rpm:"qt5-qtvirtualkeyboard-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwayland", rpm:"qt5-qtwayland~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwayland-debuginfo", rpm:"qt5-qtwayland-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwayland-debugsource", rpm:"qt5-qtwayland-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwayland-devel", rpm:"qt5-qtwayland-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwayland-devel-debuginfo", rpm:"qt5-qtwayland-devel-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwayland-examples", rpm:"qt5-qtwayland-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwayland-examples-debuginfo", rpm:"qt5-qtwayland-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebchannel", rpm:"qt5-qtwebchannel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebchannel-debuginfo", rpm:"qt5-qtwebchannel-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebchannel-debugsource", rpm:"qt5-qtwebchannel-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebchannel-devel", rpm:"qt5-qtwebchannel-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebchannel-examples", rpm:"qt5-qtwebchannel-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebchannel-examples-debuginfo", rpm:"qt5-qtwebchannel-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebengine", rpm:"qt5-qtwebengine~5.15.16~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebengine-debuginfo", rpm:"qt5-qtwebengine-debuginfo~5.15.16~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebengine-debugsource", rpm:"qt5-qtwebengine-debugsource~5.15.16~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebengine-devel", rpm:"qt5-qtwebengine-devel~5.15.16~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebengine-devel-debuginfo", rpm:"qt5-qtwebengine-devel-debuginfo~5.15.16~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebengine-devtools", rpm:"qt5-qtwebengine-devtools~5.15.16~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebengine-examples", rpm:"qt5-qtwebengine-examples~5.15.16~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebengine-examples-debuginfo", rpm:"qt5-qtwebengine-examples-debuginfo~5.15.16~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebkit", rpm:"qt5-qtwebkit~5.212.0~0.87alpha4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebkit-debuginfo", rpm:"qt5-qtwebkit-debuginfo~5.212.0~0.87alpha4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebkit-debugsource", rpm:"qt5-qtwebkit-debugsource~5.212.0~0.87alpha4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebkit-devel", rpm:"qt5-qtwebkit-devel~5.212.0~0.87alpha4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebsockets", rpm:"qt5-qtwebsockets~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebsockets-debuginfo", rpm:"qt5-qtwebsockets-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebsockets-debugsource", rpm:"qt5-qtwebsockets-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebsockets-devel", rpm:"qt5-qtwebsockets-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebsockets-devel-debuginfo", rpm:"qt5-qtwebsockets-devel-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebsockets-examples", rpm:"qt5-qtwebsockets-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebsockets-examples-debuginfo", rpm:"qt5-qtwebsockets-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebview", rpm:"qt5-qtwebview~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebview-debuginfo", rpm:"qt5-qtwebview-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebview-debugsource", rpm:"qt5-qtwebview-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebview-devel", rpm:"qt5-qtwebview-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebview-examples", rpm:"qt5-qtwebview-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebview-examples-debuginfo", rpm:"qt5-qtwebview-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtx11extras", rpm:"qt5-qtx11extras~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtx11extras-debuginfo", rpm:"qt5-qtx11extras-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtx11extras-debugsource", rpm:"qt5-qtx11extras-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtx11extras-devel", rpm:"qt5-qtx11extras-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtxmlpatterns", rpm:"qt5-qtxmlpatterns~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtxmlpatterns-debuginfo", rpm:"qt5-qtxmlpatterns-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtxmlpatterns-debugsource", rpm:"qt5-qtxmlpatterns-debugsource~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtxmlpatterns-devel", rpm:"qt5-qtxmlpatterns-devel~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtxmlpatterns-devel-debuginfo", rpm:"qt5-qtxmlpatterns-devel-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtxmlpatterns-examples", rpm:"qt5-qtxmlpatterns-examples~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtxmlpatterns-examples-debuginfo", rpm:"qt5-qtxmlpatterns-examples-debuginfo~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-rpm-macros", rpm:"qt5-rpm-macros~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-srpm-macros", rpm:"qt5-srpm-macros~5.15.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5ct", rpm:"qt5ct~1.1~24.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5ct-debuginfo", rpm:"qt5ct-debuginfo~1.1~24.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5ct-debugsource", rpm:"qt5ct-debugsource~1.1~24.fc40", rls:"FC40"))) {
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

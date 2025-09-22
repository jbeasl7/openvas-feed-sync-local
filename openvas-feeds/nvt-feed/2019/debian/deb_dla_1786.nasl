# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891786");
  script_cve_id("CVE-2018-15518", "CVE-2018-19869", "CVE-2018-19870", "CVE-2018-19871", "CVE-2018-19873");
  script_tag(name:"creation_date", value:"2019-05-15 02:00:11 +0000 (Wed, 15 May 2019)");
  script_version("2025-02-12T05:37:43+0000");
  script_tag(name:"last_modification", value:"2025-02-12 05:37:43 +0000 (Wed, 12 Feb 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-11 20:11:38 +0000 (Tue, 11 Feb 2025)");

  script_name("Debian: Security Advisory (DLA-1786-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1786-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/DLA-1786-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qt4-x11' package(s) announced via the DLA-1786-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple issues have been addressed in Qt4.

CVE-2018-15518

A double-free or corruption during parsing of a specially crafted illegal XML document.

CVE-2018-19869

A malformed SVG image could cause a segmentation fault in qsvghandler.cpp.

CVE-2018-19870

A malformed GIF image might have caused a NULL pointer dereference in QGifHandler resulting in a segmentation fault.

CVE-2018-19871

There was an uncontrolled resource consumption in QTgaFile.

CVE-2018-19873

QBmpHandler had a buffer overflow via BMP data.

For Debian 8 Jessie, these problems have been fixed in version 4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2.

We recommend that you upgrade your qt4-x11 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'qt4-x11' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-assistant", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-core", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-dbg", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-dbus", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-declarative", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-declarative-folderlistmodel", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-declarative-gestures", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-declarative-particles", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-declarative-shaders", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-designer", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-designer-dbg", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-dev", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-dev-bin", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-gui", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-help", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-network", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-opengl", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-opengl-dev", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-phonon", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-private-dev", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-qt3support", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-qt3support-dbg", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-script", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-script-dbg", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-scripttools", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-ibase", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-mysql", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-odbc", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-psql", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-sqlite", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-sqlite2", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-tds", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-svg", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-test", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-webkit", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-webkit-dbg", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-xml", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-xmlpatterns", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-xmlpatterns-dbg", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqtcore4", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqtdbus4", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqtgui4", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qdbus", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-bin-dbg", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-default", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-demos", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-demos-dbg", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-designer", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-dev-tools", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-doc", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-doc-html", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-linguist-tools", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-qmake", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-qmlviewer", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-qtconfig", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qtcore4-l10n", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
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

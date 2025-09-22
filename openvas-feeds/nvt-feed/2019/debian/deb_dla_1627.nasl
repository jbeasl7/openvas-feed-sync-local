# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891627");
  script_cve_id("CVE-2018-15518", "CVE-2018-19870", "CVE-2018-19873");
  script_tag(name:"creation_date", value:"2019-01-02 23:00:00 +0000 (Wed, 02 Jan 2019)");
  script_version("2025-02-12T05:37:43+0000");
  script_tag(name:"last_modification", value:"2025-02-12 05:37:43 +0000 (Wed, 12 Feb 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-11 20:11:38 +0000 (Tue, 11 Feb 2025)");

  script_name("Debian: Security Advisory (DLA-1627-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1627-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/DLA-1627-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qtbase-opensource-src' package(s) announced via the DLA-1627-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple issues were fixed in Qt.

CVE-2018-15518

A double-free or corruption during parsing of a specially crafted illegal XML document.

CVE-2018-19870

A malformed GIF image might have caused a NULL pointer dereference in QGifHandler resulting in a segmentation fault.

CVE-2018-19873

QBmpHandler had a buffer overflow via BMP data.

For Debian 8 Jessie, these problems have been fixed in version 5.3.2+dfsg-4+deb8u3.

We recommend that you upgrade your qtbase-opensource-src packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'qtbase-opensource-src' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libqt5concurrent5", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5core5a", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5dbus5", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5gui5", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5network5", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5opengl5", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5opengl5-dev", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5printsupport5", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5-mysql", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5-odbc", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5-psql", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5-sqlite", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5-tds", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5test5", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5widgets5", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5xml5", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt5-default", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt5-qmake", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qtbase5-dbg", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qtbase5-dev", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qtbase5-dev-tools", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qtbase5-dev-tools-dbg", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qtbase5-doc-html", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qtbase5-examples", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qtbase5-examples-dbg", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qtbase5-private-dev", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8"))) {
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

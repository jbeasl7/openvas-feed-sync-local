# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2010.1988");
  script_cve_id("CVE-2009-0945", "CVE-2009-1687", "CVE-2009-1690", "CVE-2009-1698", "CVE-2009-1699", "CVE-2009-1711", "CVE-2009-1712", "CVE-2009-1713", "CVE-2009-1725", "CVE-2009-2700");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-10 02:48:38 +0000 (Sat, 10 Feb 2024)");

  script_name("Debian: Security Advisory (DSA-1988-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1988-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/DSA-1988-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1988");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qt4-x11' package(s) announced via the DSA-1988-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in qt4-x11, a cross-platform C++ application framework. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-0945

Array index error in the insertItemBefore method in WebKit, as used in qt4-x11, allows remote attackers to execute arbitrary code.

CVE-2009-1687

The JavaScript garbage collector in WebKit, as used in qt4-x11 does not properly handle allocation failures, which allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via a crafted HTML document that triggers write access to an 'offset of a NULL pointer.

CVE-2009-1690

Use-after-free vulnerability in WebKit, as used in qt4-x11, allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) by setting an unspecified property of an HTML tag that causes child elements to be freed and later accessed when an HTML error occurs.

CVE-2009-1698

WebKit in qt4-x11 does not initialize a pointer during handling of a Cascading Style Sheets (CSS) attr function call with a large numerical argument, which allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via a crafted HTML document.

CVE-2009-1699

The XSL stylesheet implementation in WebKit, as used in qt4-x11 does not properly handle XML external entities, which allows remote attackers to read arbitrary files via a crafted DTD.

CVE-2009-1711

WebKit in qt4-x11 does not properly initialize memory for Attr DOM objects, which allows remote attackers to execute arbitrary code or cause a denial of service (application crash) via a crafted HTML document.

CVE-2009-1712

WebKit in qt4-x11 does not prevent remote loading of local Java applets, which allows remote attackers to execute arbitrary code, gain privileges, or obtain sensitive information via an APPLET or OBJECT element.

CVE-2009-1713

The XSLT functionality in WebKit, as used in qt4-x11 does not properly implement the document function, which allows remote attackers to read arbitrary local files and files from different security zones.

CVE-2009-1725

WebKit in qt4-x11 does not properly handle numeric character references, which allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via a crafted HTML document.

CVE-2009-2700

qt4-x11 does not properly handle a '0' character in a domain name in the Subject Alternative Name field of an X.509 certificate, which allows man-in-the-middle attackers to spoof arbitrary SSL servers via a crafted certificate issued by a legitimate Certification Authority.

The oldstable distribution (etch) is not affected by these problems.

For the stable distribution (lenny), these problems have been fixed in version 4.4.3-1+lenny1.

For the testing ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qt4-x11' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-assistant", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-core", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-dbg", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-dbus", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-designer", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-dev", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-gui", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-help", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-network", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-opengl", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-opengl-dev", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-qt3support", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-script", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-ibase", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-mysql", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-odbc", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-psql", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-sqlite", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-sqlite2", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-svg", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-test", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-webkit", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-webkit-dbg", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-xml", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-xmlpatterns", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-xmlpatterns-dbg", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqtcore4", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqtgui4", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-demos", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-designer", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-dev-tools", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-doc", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-doc-html", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-qmake", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-qtconfig", ver:"4.4.3-1+lenny1", rls:"DEB5"))) {
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

# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64254");
  script_cve_id("CVE-2009-1392", "CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1834", "CVE-2009-1835", "CVE-2009-1836", "CVE-2009-1837", "CVE-2009-1838", "CVE-2009-1839", "CVE-2009-1840", "CVE-2009-1841", "CVE-2009-2061");
  script_tag(name:"creation_date", value:"2009-06-23 13:49:15 +0000 (Tue, 23 Jun 2009)");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 16:03:54 +0000 (Fri, 02 Feb 2024)");

  script_name("Debian: Security Advisory (DSA-1820-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1820-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1820-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1820");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xulrunner' package(s) announced via the DSA-1820-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in Xulrunner, a runtime environment for XUL applications, such as the Iceweasel web browser. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-1392

Several issues in the browser engine have been discovered, which can result in the execution of arbitrary code. (MFSA 2009-24)

CVE-2009-1832

It is possible to execute arbitrary code via vectors involving 'double frame construction.' (MFSA 2009-24)

CVE-2009-1833

Jesse Ruderman and Adam Hauner discovered a problem in the JavaScript engine, which could lead to the execution of arbitrary code. (MFSA 2009-24)

CVE-2009-1834

Pavel Cvrcek discovered a potential issue leading to a spoofing attack on the location bar related to certain invalid unicode characters. (MFSA 2009-25)

CVE-2009-1835

Gregory Fleischer discovered that it is possible to read arbitrary cookies via a crafted HTML document. (MFSA 2009-26)

CVE-2009-1836

Shuo Chen, Ziqing Mao, Yi-Min Wang and Ming Zhang reported a potential man-in-the-middle attack, when using a proxy due to insufficient checks on a certain proxy response. (MFSA 2009-27)

CVE-2009-1837

Jakob Balle and Carsten Eiram reported a race condition in the NPObjWrapper_NewResolve function that can be used to execute arbitrary code. (MFSA 2009-28)

CVE-2009-1838

moz_bug_r_a4 discovered that it is possible to execute arbitrary JavaScript with chrome privileges due to an error in the garbage-collection implementation. (MFSA 2009-29)

CVE-2009-1839

Adam Barth and Collin Jackson reported a potential privilege escalation when loading a file::resource via the location bar. (MFSA 2009-30)

CVE-2009-1840

Wladimir Palant discovered that it is possible to bypass access restrictions due to a lack of content policy check, when loading a script file into a XUL document. (MFSA 2009-31)

CVE-2009-1841

moz_bug_r_a4 reported that it is possible for scripts from page content to run with elevated privileges and thus potentially executing arbitrary code with the object's chrome privileges. (MFSA 2009-32)

For the stable distribution (lenny), these problems have been fixed in version 1.9.0.11-0lenny1.

As indicated in the Etch release notes, security support for the Mozilla products in the oldstable distribution needed to be stopped before the end of the regular Etch security maintenance life cycle. You are strongly encouraged to upgrade to stable or switch to a still supported browser.

For the testing distribution (squeeze), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 1.9.0.11-1.

We recommend that you upgrade your xulrunner packages.");

  script_tag(name:"affected", value:"'xulrunner' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libmozillainterfaces-java", ver:"1.9.0.11-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs-dev", ver:"1.9.0.11-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs1d", ver:"1.9.0.11-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs1d-dbg", ver:"1.9.0.11-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-xpcom", ver:"1.9.0.11-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"spidermonkey-bin", ver:"1.9.0.11-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.11-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9-dbg", ver:"1.9.0.11-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9-gnome-support", ver:"1.9.0.11-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.0.11-0lenny1", rls:"DEB5"))) {
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

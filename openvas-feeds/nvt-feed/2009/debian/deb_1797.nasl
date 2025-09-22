# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63962");
  script_cve_id("CVE-2009-0652", "CVE-2009-1302", "CVE-2009-1303", "CVE-2009-1304", "CVE-2009-1305", "CVE-2009-1306", "CVE-2009-1307", "CVE-2009-1308", "CVE-2009-1309", "CVE-2009-1311", "CVE-2009-1312");
  script_tag(name:"creation_date", value:"2009-05-11 18:24:31 +0000 (Mon, 11 May 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1797-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1797-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1797-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1797");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xulrunner' package(s) announced via the DSA-1797-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in Xulrunner, a runtime environment for XUL applications, such as the Iceweasel web browser. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-0652

Moxie Marlinspike discovered that Unicode box drawing characters inside of internationalised domain names could be used for phishing attacks.

CVE-2009-1302

Olli Pettay, Martijn Wargers, Mats Palmgren, Oleg Romashin, Jesse Ruderman and Gary Kwong reported crashes in the layout engine, which might allow the execution of arbitrary code.

CVE-2009-1303

Olli Pettay, Martijn Wargers, Mats Palmgren, Oleg Romashin, Jesse Ruderman and Gary Kwong reported crashes in the layout engine, which might allow the execution of arbitrary code.

CVE-2009-1304

Igor Bukanov and Bob Clary discovered crashes in the Javascript engine, which might allow the execution of arbitrary code.

CVE-2009-1305

Igor Bukanov and Bob Clary discovered crashes in the Javascript engine, which might allow the execution of arbitrary code.

CVE-2009-1306

Daniel Veditz discovered that the Content-Disposition: header is ignored within the jar: URI scheme.

CVE-2009-1307

Gregory Fleischer discovered that the same-origin policy for Flash files is improperly enforced for files loaded through the view-source scheme, which may result in bypass of cross-domain policy restrictions.

CVE-2009-1308

Cefn Hoile discovered that sites, which allow the embedding of third-party stylesheets are vulnerable to cross-site scripting attacks through XBL bindings.

CVE-2009-1309

'moz_bug_r_a4' discovered bypasses of the same-origin policy in the XMLHttpRequest Javascript API and the XPCNativeWrapper.

CVE-2009-1311

Paolo Amadini discovered that incorrect handling of POST data when saving a web site with an embedded frame may lead to information disclosure.

CVE-2009-1312

It was discovered that Iceweasel allows Refresh: headers to redirect to Javascript URIs, resulting in cross-site scripting.

For the stable distribution (lenny), these problems have been fixed in version 1.9.0.9-0lenny2.

As indicated in the Etch release notes, security support for the Mozilla products in the oldstable distribution needed to be stopped before the end of the regular Etch security maintenance life cycle. You are strongly encouraged to upgrade to stable or switch to a still supported browser.

For the unstable distribution (sid), these problems have been fixed in version 1.9.0.9-1.

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

  if(!isnull(res = isdpkgvuln(pkg:"libmozillainterfaces-java", ver:"1.9.0.9-0lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs-dev", ver:"1.9.0.9-0lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs1d", ver:"1.9.0.9-0lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs1d-dbg", ver:"1.9.0.9-0lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-xpcom", ver:"1.9.0.9-0lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"spidermonkey-bin", ver:"1.9.0.9-0lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.9-0lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9-dbg", ver:"1.9.0.9-0lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9-gnome-support", ver:"1.9.0.9-0lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.0.9-0lenny2", rls:"DEB5"))) {
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

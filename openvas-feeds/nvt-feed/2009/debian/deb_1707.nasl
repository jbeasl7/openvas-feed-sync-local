# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63220");
  script_cve_id("CVE-2007-3074", "CVE-2008-5500", "CVE-2008-5503", "CVE-2008-5504", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5510", "CVE-2008-5511", "CVE-2008-5512", "CVE-2008-5513");
  script_tag(name:"creation_date", value:"2009-01-20 21:42:09 +0000 (Tue, 20 Jan 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1707-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1707-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1707-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1707");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceweasel' package(s) announced via the DSA-1707-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Iceweasel web browser, an unbranded version of the Firefox browser. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-5500

Jesse Ruderman discovered that the layout engine is vulnerable to DoS attacks that might trigger memory corruption and an integer overflow. (MFSA 2008-60)

CVE-2008-5503

Boris Zbarsky discovered that an information disclosure attack could be performed via XBL bindings. (MFSA 2008-61)

CVE-2008-5504

It was discovered that attackers could run arbitrary JavaScript with chrome privileges via vectors related to the feed preview. (MFSA 2008-62)

CVE-2008-5506

Marius Schilder discovered that it is possible to obtain sensible data via a XMLHttpRequest. (MFSA 2008-64)

CVE-2008-5507

Chris Evans discovered that it is possible to obtain sensible data via a JavaScript URL. (MFSA 2008-65)

CVE-2008-5508

Chip Salzenberg discovered possible phishing attacks via URLs with leading whitespaces or control characters. (MFSA 2008-66)

CVE-2008-5510

Kojima Hajime and Jun Muto discovered that escaped null characters were ignored by the CSS parser and could lead to the bypass of protection mechanisms (MFSA 2008-67)

CVE-2008-5511

It was discovered that it is possible to perform cross-site scripting attacks via an XBL binding to an 'unloaded document.' (MFSA 2008-68)

CVE-2008-5512

It was discovered that it is possible to run arbitrary JavaScript with chrome privileges via unknown vectors. (MFSA 2008-68)

CVE-2008-5513

moz_bug_r_a4 discovered that the session-restore feature does not properly sanitise input leading to arbitrary injections. This issue could be used to perform an XSS attack or run arbitrary JavaScript with chrome privileges. (MFSA 2008-69)

For the stable distribution (etch) these problems have been fixed in version 2.0.0.19-0etch1.

For the testing distribution (lenny) and the unstable distribution (sid) these problems have been fixed in version 3.0.5-1. Please note iceweasel in Lenny links dynamically against xulrunner.

We recommend that you upgrade your iceweasel package.");

  script_tag(name:"affected", value:"'iceweasel' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"2.0.0.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"2.0.0.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel", ver:"2.0.0.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-dbg", ver:"2.0.0.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-dom-inspector", ver:"2.0.0.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-gnome-support", ver:"2.0.0.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox", ver:"2.0.0.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-dom-inspector", ver:"2.0.0.19-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-gnome-support", ver:"2.0.0.19-0etch1", rls:"DEB4"))) {
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

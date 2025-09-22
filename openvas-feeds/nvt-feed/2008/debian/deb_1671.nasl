# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61934");
  script_cve_id("CVE-2008-0017", "CVE-2008-4582", "CVE-2008-5012", "CVE-2008-5013", "CVE-2008-5014", "CVE-2008-5017", "CVE-2008-5018", "CVE-2008-5019", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5023", "CVE-2008-5024", "CVE-2008-5052");
  script_tag(name:"creation_date", value:"2008-12-03 17:25:22 +0000 (Wed, 03 Dec 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1671-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1671-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1671-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1671");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceweasel' package(s) announced via the DSA-1671-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Iceweasel webbrowser, an unbranded version of the Firefox browser. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-0017

Justin Schuh discovered that a buffer overflow in the http-index-format parser could lead to arbitrary code execution.

CVE-2008-4582

Liu Die Yu discovered an information leak through local shortcut files.

CVE-2008-5012

Georgi Guninski, Michal Zalewski and Chris Evan discovered that the canvas element could be used to bypass same-origin restrictions.

CVE-2008-5013

It was discovered that insufficient checks in the Flash plugin glue code could lead to arbitrary code execution.

CVE-2008-5014

Jesse Ruderman discovered that a programming error in the window.__proto__.__proto__ object could lead to arbitrary code execution.

CVE-2008-5017

It was discovered that crashes in the layout engine could lead to arbitrary code execution.

CVE-2008-5018

It was discovered that crashes in the Javascript engine could lead to arbitrary code execution.

CVE-2008-5021

It was discovered that a crash in the nsFrameManager might lead to the execution of arbitrary code.

CVE-2008-5022

moz_bug_r_a4 discovered that the same-origin check in nsXMLHttpRequest::NotifyEventListeners() could be bypassed.

CVE-2008-5023

Collin Jackson discovered that the -moz-binding property bypasses security checks on codebase principals.

CVE-2008-5024

Chris Evans discovered that quote characters were improperly escaped in the default namespace of E4X documents.

For the stable distribution (etch), these problems have been fixed in version 2.0.0.18-0etch1.

For the upcoming stable distribution (lenny) and the unstable distribution (sid), these problems have been fixed in version 3.0.4-1 of iceweasel and version 1.9.0.4-1 of xulrunner. Packages for arm and mips will be provided soon.

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.18-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"2.0.0.18-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"2.0.0.18-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel", ver:"2.0.0.18-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-dbg", ver:"2.0.0.18-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-dom-inspector", ver:"2.0.0.18-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-gnome-support", ver:"2.0.0.18-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox", ver:"2.0.0.18-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-dom-inspector", ver:"2.0.0.18-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-gnome-support", ver:"2.0.0.18-0etch1", rls:"DEB4"))) {
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

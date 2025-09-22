# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58695");
  script_cve_id("CVE-2007-1095", "CVE-2007-2292", "CVE-2007-3511", "CVE-2007-5334", "CVE-2007-5335", "CVE-2007-5337", "CVE-2007-5338", "CVE-2007-5339", "CVE-2007-5340");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1396-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1396-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/DSA-1396-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1396");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceweasel' package(s) announced via the DSA-1396-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Iceweasel web browser, an unbranded version of the Firefox browser. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-1095

Michal Zalewski discovered that the unload event handler had access to the address of the next page to be loaded, which could allow information disclosure or spoofing.

CVE-2007-2292

Stefano Di Paola discovered that insufficient validation of user names used in Digest authentication on a web site allows HTTP response splitting attacks.

CVE-2007-3511

It was discovered that insecure focus handling of the file upload control can lead to information disclosure. This is a variant of CVE-2006-2894.

CVE-2007-5334

Eli Friedman discovered that web pages written in Xul markup can hide the titlebar of windows, which can lead to spoofing attacks.

CVE-2007-5337

Georgi Guninski discovered the insecure handling of smb:// and sftp:// URI schemes may lead to information disclosure. This vulnerability is only exploitable if Gnome-VFS support is present on the system.

CVE-2007-5338

moz_bug_r_a4 discovered that the protection scheme offered by XPCNativeWrappers could be bypassed, which might allow privilege escalation.

CVE-2007-5339

L. David Baron, Boris Zbarsky, Georgi Guninski, Paul Nickerson, Olli Pettay, Jesse Ruderman, Vladimir Sukhoy, Daniel Veditz, and Martijn Wargers discovered crashes in the layout engine, which might allow the execution of arbitrary code.

CVE-2007-5340

Igor Bukanov, Eli Friedman, and Jesse Ruderman discovered crashes in the JavaScript engine, which might allow the execution of arbitrary code.

The Mozilla products in the oldstable distribution (sarge) are no longer supported with security updates.

For the stable distribution (etch) these problems have been fixed in version 2.0.0.6+2.0.0.8-0etch1. Builds for arm and sparc will be provided later.

For the unstable distribution (sid) these problems have been fixed in version 2.0.0.8-1.

We recommend that you upgrade your iceweasel packages.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.6+2.0.0.8-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"2.0.0.6+2.0.0.8-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"2.0.0.6+2.0.0.8-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel", ver:"2.0.0.6+2.0.0.8-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-dbg", ver:"2.0.0.6+2.0.0.8-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-dom-inspector", ver:"2.0.0.6+2.0.0.8-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-gnome-support", ver:"2.0.0.6+2.0.0.8-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox", ver:"2.0.0.6+2.0.0.8-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-dom-inspector", ver:"2.0.0.6+2.0.0.8-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-gnome-support", ver:"2.0.0.6+2.0.0.8-0etch1", rls:"DEB4"))) {
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

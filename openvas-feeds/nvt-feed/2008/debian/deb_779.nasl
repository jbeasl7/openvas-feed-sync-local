# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55205");
  script_cve_id("CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2262", "CVE-2005-2263", "CVE-2005-2264", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2267", "CVE-2005-2268", "CVE-2005-2269", "CVE-2005-2270");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-779-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-779-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-779-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-779");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mozilla-firefox' package(s) announced via the DSA-779-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"We experienced that the update for Mozilla Firefox from DSA 779-1 unfortunately was a regression in several cases. Since the usual praxis of backporting apparently does not work, this update is basically version 1.0.6 with the version number rolled back, and hence still named 1.0.4-*. For completeness below is the original advisory text:

Several problems have been discovered in Mozilla Firefox, a lightweight web browser based on Mozilla. The Common Vulnerabilities and Exposures project identifies the following problems:

CAN-2005-2260

The browser user interface does not properly distinguish between user-generated events and untrusted synthetic events, which makes it easier for remote attackers to perform dangerous actions that normally could only be performed manually by the user.

CAN-2005-2261

XML scripts ran even when Javascript disabled.

CAN-2005-2262

The user can be tricked to executing arbitrary JavaScript code by using a JavaScript URL as wallpaper.

CAN-2005-2263

It is possible for a remote attacker to execute a callback function in the context of another domain (i.e. frame).

CAN-2005-2264

By opening a malicious link in the sidebar it is possible for remote attackers to steal sensitive information.

CAN-2005-2265

Missing input sanitising of InstallVersion.compareTo() can cause the application to crash.

CAN-2005-2266

Remote attackers could steal sensitive information such as cookies and passwords from web sites by accessing data in alien frames.

CAN-2005-2267

By using standalone applications such as Flash and QuickTime to open a javascript: URL, it is possible for a remote attacker to steal sensitive information and possibly execute arbitrary code.

CAN-2005-2268

It is possible for a Javascript dialog box to spoof a dialog box from a trusted site and facilitates phishing attacks.

CAN-2005-2269

Remote attackers could modify certain tag properties of DOM nodes that could lead to the execution of arbitrary script or code.

CAN-2005-2270

The Mozilla browser family does not properly clone base objects, which allows remote attackers to execute arbitrary code.

The old stable distribution (woody) is not affected by these problems.

For the stable distribution (sarge) these problems have been fixed in version 1.0.4-2sarge3.

For the unstable distribution (sid) these problems have been fixed in version 1.0.6-1.

We recommend that you upgrade your Mozilla Firefox packages.");

  script_tag(name:"affected", value:"'mozilla-firefox' package(s) on Debian 3.1.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox", ver:"1.0.4-2sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-dom-inspector", ver:"1.0.4-2sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-gnome-support", ver:"1.0.4-2sarge3", rls:"DEB3.1"))) {
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

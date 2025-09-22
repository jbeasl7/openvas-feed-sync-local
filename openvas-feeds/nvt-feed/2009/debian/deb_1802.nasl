# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64037");
  script_cve_id("CVE-2009-1381", "CVE-2009-1578", "CVE-2009-1579", "CVE-2009-1580", "CVE-2009-1581");
  script_tag(name:"creation_date", value:"2009-05-25 18:59:33 +0000 (Mon, 25 May 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1802-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1802-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1802-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1802");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'squirrelmail' package(s) announced via the DSA-1802-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in SquirrelMail, a webmail application. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-1578

Cross site scripting was possible through a number of pages which allowed an attacker to steal sensitive session data.

CVE-2009-1579, CVE-2009-1381 Code injection was possible when SquirrelMail was configured to use the map_yp_alias function to authenticate users. This is not the default.

CVE-2009-1580

It was possible to hijack an active user session by planting a specially crafted cookie into the user's browser.

CVE-2009-1581

Specially crafted HTML emails could use the CSS positioning feature to place email content over the SquirrelMail user interface, allowing for phishing.

For the old stable distribution (etch), these problems have been fixed in version 1.4.9a-5.

For the stable distribution (lenny), these problems have been fixed in version 1.4.15-4+lenny2.

For the unstable distribution (sid), these problems have been fixed in version 1.4.19-1.

We recommend that you upgrade your squirrelmail package.");

  script_tag(name:"affected", value:"'squirrelmail' package(s) on Debian 4, Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"squirrelmail", ver:"2:1.4.9a-5", rls:"DEB4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"squirrelmail", ver:"2:1.4.15-4+lenny2", rls:"DEB5"))) {
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

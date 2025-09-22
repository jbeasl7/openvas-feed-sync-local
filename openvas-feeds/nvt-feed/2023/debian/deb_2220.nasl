# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2011.2220");
  script_cve_id("CVE-2011-1685", "CVE-2011-1686", "CVE-2011-1687", "CVE-2011-1688", "CVE-2011-1689", "CVE-2011-1690");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-01T14:37:13+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:13 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2220-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");

  script_xref(name:"Advisory-ID", value:"DSA-2220-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2220-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2220");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'request-tracker3.6, request-tracker3.8' package(s) announced via the DSA-2220-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Request Tracker, an issue tracking system.

CVE-2011-1685

If the external custom field feature is enabled, Request Tracker allows authenticated users to execute arbitrary code with the permissions of the web server, possible triggered by a cross-site request forgery attack. (External custom fields are disabled by default.)

CVE-2011-1686

Multiple SQL injection attacks allow authenticated users to obtain data from the database in an unauthorized way.

CVE-2011-1687

An information leak allows an authenticated privileged user to obtain sensitive information, such as encrypted passwords, via the search interface.

CVE-2011-1688

When running under certain web servers (such as Lighttpd), Request Tracker is vulnerable to a directory traversal attack, allowing attackers to read any files accessible to the web server. Request Tracker instances running under Apache or Nginx are not affected.

CVE-2011-1689

Request Tracker contains multiple cross-site scripting vulnerabilities.

CVE-2011-1690

Request Tracker enables attackers to redirect authentication credentials supplied by legitimate users to third-party servers.

For the oldstable distribution (lenny), these problems have been fixed in version 3.6.7-5+lenny6 of the request-tracker3.6 package.

For the stable distribution (squeeze), these problems have been fixed in version 3.8.8-7+squeeze1 of the request-tracker3.8 package.

For the testing distribution (wheezy) and the unstable distribution (sid), these problems have been fixed in version 3.8.10-1 of the request-tracker3.8 package.

We recommend that you upgrade your Request Tracker packages.");

  script_tag(name:"affected", value:"'request-tracker3.6, request-tracker3.8' package(s) on Debian 5, Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"request-tracker3.6", ver:"3.6.7-5+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.6-apache2", ver:"3.6.7-5+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.6-clients", ver:"3.6.7-5+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.6-db-mysql", ver:"3.6.7-5+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.6-db-postgresql", ver:"3.6.7-5+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.6-db-sqlite", ver:"3.6.7-5+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"request-tracker3.8", ver:"3.8.8-7+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.8-apache2", ver:"3.8.8-7+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.8-clients", ver:"3.8.8-7+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.8-db-mysql", ver:"3.8.8-7+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.8-db-postgresql", ver:"3.8.8-7+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.8-db-sqlite", ver:"3.8.8-7+squeeze1", rls:"DEB6"))) {
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

# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53740");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2002-2260");
  script_name("Debian Security Advisory DSA 218-1 (bugzilla)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20218-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6257");
  script_tag(name:"insight", value:"A cross site scripting vulnerability has been reported for Bugzilla, a
web-based bug tracking system.  Bugzilla does not properly sanitize
any input submitted by users.  As a result, it is possible for a
remote attacker to create a malicious link containing script code
which will be executed in the browser of a legitimate user, in the
context of the website running Bugzilla.  This issue may be exploited
to steal cookie-based authentication credentials from legitimate users
of the website running the vulnerable software.

This vulnerability only affects users who have the 'quips' feature
enabled and who upgraded from version 2.10 which did not exist inside
of Debian.  The Debian package history of Bugzilla starts with 1.13
and jumped to 2.13.  However, users could have installed version 2.10
prior to the Debian package.

For the current stable distribution (woody) this problem has been
fixed in version 2.14.2-0woody3.

The old stable distribution (potato) does not contain a Bugzilla
package.

For the unstable distribution (sid) this problem will be fixed soon.");

  script_tag(name:"solution", value:"We recommend that you upgrade your bugzilla packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to bugzilla
announced via advisory DSA 218-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"bugzilla-doc", ver:"2.14.2-0woody3", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"bugzilla", ver:"2.14.2-0woody3", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

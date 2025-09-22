# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53419");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-1115", "CVE-2002-1116");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 161-1 (mantis)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20161-1");
  script_tag(name:"insight", value:"A problem with user privileges has been discovered in the Mantis
package, a PHP based bug tracking system.  The Mantis system didn't
check whether a user is permitted to view a bug, but displays it right
away if the user entered a valid bug id.

Another bug in Mantis caused the 'View Bugs' page to list bugs from
both public and private projects when no projects are accessible to
the current user.

These problems have been fixed in version 0.17.1-2.5 for the current
stable distribution (woody) and in version 0.17.5-2 for the unstable
distribution (sid).  The old stable distribution (potato) is not
affected, since it doesn't contain the mantis package.");

  script_tag(name:"solution", value:"We recommend that you upgrade your mantis packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to mantis
announced via advisory DSA 161-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"mantis", ver:"0.17.1-2.5", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

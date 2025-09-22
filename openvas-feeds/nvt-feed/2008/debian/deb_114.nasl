# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53393");
  script_cve_id("CVE-2002-0300");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Debian Security Advisory DSA 114-1 (gnujsp)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20114-1");
  script_tag(name:"insight", value:"Thomas Springer found a vulnerability in GNUJSP, a Java servlet that
allows you to insert Java source code into HTML files.  The problem
can be used to bypass access restrictions in the web server.  An
attacker can view the contents of directories and download files
directly rather then receiving their HTML output.  This means that the
source code of scripts could also be revealed.

The problem was fixed by Stefan Gybas, who maintains the Debian
package of GNUJSP.  It is fixed in version 1.0.0-5 for the stable
release of Debian GNU/Linux.

The versions in testing and unstable are the same as the one in stable
so they are vulnerable, too.  You can install the fixed version this
advisory refers to on these systems to solve the problem as this
package is architecture independent.");

  script_tag(name:"solution", value:"We recommend that you upgrade your gnujsp package immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to gnujsp
announced via advisory DSA 114-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"gnujsp", ver:"1.0.0-5", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

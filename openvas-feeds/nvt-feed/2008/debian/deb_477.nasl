# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53707");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2004-0372");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Debian Security Advisory DSA 477-1 (xine-ui)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20477-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9939");
  script_tag(name:"insight", value:"Shaun Colley discovered a problem in xine-ui, the xine video player
user interface.  A script contained in the package to possibly remedy
a problem or report a bug does not create temporary files in a secure
fashion.  This could allow a local attacker to overwrite files with
the privileges of the user invoking xine.

This update also removes the bug reporting facility since bug reports
can't be processed upstream anymore.

For the stable distribution (woody) this problem has been fixed in
version 0.9.8-5.

For the unstable distribution (sid) this problem will be fixed soon.");

  script_tag(name:"solution", value:"We recommend that you upgrade your xine-ui package.");
  script_tag(name:"summary", value:"The remote host is missing an update to xine-ui
announced via advisory DSA 477-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"xine-ui", ver:"0.9.8-5.1", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

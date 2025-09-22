# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53313");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0015");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 233-1 (cvs)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(2\.2|3\.0)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20233-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6650");
  script_tag(name:"insight", value:"Stefan Esser discovered a problem in cvs, a concurrent versions
system, which is used for many Free Software projects.  The current
version contains a flaw that can be used by a remote attacker to
execute arbitrary code on the CVS server under the user id the CVS
server runs as.  Anonymous read-only access is sufficient to exploit
this problem.

For the stable distribution (woody) this problem has been
fixed in version 1.11.1p1debian-8.1.

For the old stable distribution (potato) this problem has been fixed
in version 1.10.7-9.2.

For the unstable distribution (sid) this problem will be fixed soon.");

  script_tag(name:"solution", value:"We recommend that you upgrade your cvs package immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to cvs
announced via advisory DSA 233-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"cvs-doc", ver:"1.10.7-9.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cvs", ver:"1.10.7-9.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cvs", ver:"1.11.1p1debian-8.1", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

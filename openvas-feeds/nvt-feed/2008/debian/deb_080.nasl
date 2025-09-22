# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53571");
  script_cve_id("CVE-2001-0834");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_name("Debian Security Advisory DSA 080-1 (htdig)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20080-1");
  script_tag(name:"insight", value:"Nergal reported a vulnerability in the htsearch program which is
distributed as part of the ht://Dig package, an indexing and searching
system for small domains or intranets.  Using former versions it was
able to pass the parameter `-c' to the cgi program in order to use a
different configuration file.

A malicious user could point htsearch to a file like `/dev/zero' and
let the server run in an endless loop, trying to read config
parameters.  If the user has write permission on the server he can
point the program to it and retrieve any file readable by the webserver
user id.

This problem has been fixed in version of 3.1.5-2.1 for Debian
GNU/Linux 2.2.");

  script_tag(name:"solution", value:"We recommend that you upgrade your htdig package immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to htdig
announced via advisory DSA 080-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"htdig-doc", ver:"3.1.5-2.0potato.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"htdig", ver:"3.1.5-2.0potato.1", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

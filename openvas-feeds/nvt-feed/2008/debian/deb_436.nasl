# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53144");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0038", "CVE-2003-0965", "CVE-2003-0991");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 436-2 (mailman)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20436-2");
  script_tag(name:"insight", value:"Several vulnerabilities have been fixed in the mailman package:

  - CVE-2003-0038 - potential cross-site scripting via certain CGI
parameters (not known to be exploitable in this version)

  - CVE-2003-0965 - cross-site scripting in the administrative
interface

  - CVE-2003-0991 - certain malformed email commands could cause the
mailman process to crash

The cross-site scripting vulnerabilities could allow an attacker to
perform administrative operations without authorization, by stealing a
session cookie.

In the process of fixing these vulnerabilities for DSA 436-1, a bug
was introduced which could cause mailman to crash on certain malformed
messages.

For the current stable distribution (woody) this problem has been
fixed in version 2.0.11-1woody8.

The update for the unstable distribution did not share the bug
introduced in DSA 436-1.

We recommend that you update your mailman package.");
  script_tag(name:"summary", value:"The remote host is missing an update to mailman
announced via advisory DSA 436-2.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"mailman", ver:"2.0.11-1woody8", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

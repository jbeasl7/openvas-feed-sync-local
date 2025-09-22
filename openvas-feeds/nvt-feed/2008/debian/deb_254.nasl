# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53723");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-1051", "CVE-2002-1364", "CVE-2002-1386", "CVE-2002-1387");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 254-1 (traceroute-nanog)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(2\.2|3\.0)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20254-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4956");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6166");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6274");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6275");
  script_tag(name:"insight", value:"A vulnerability has been discovered in NANOG traceroute, an enhanced
version of the Van Jacobson/BSD traceroute program.  A buffer overflow
occurs in the 'get_origin()' function.  Due to insufficient bounds
checking performed by the whois parser, it may be possible to corrupt
memory on the system stack.  This vulnerability can be exploited by a
remote attacker to gain root privileges on a target host.  Though,
most probably not in Debian.

The Common Vulnerabilities and Exposures (CVE) project additionally
identified the following vulnerabilities which were already fixed in
the Debian version in stable (woody) and oldstable (potato) and are
mentioned here for completeness (and since other distributions had to
release a separate advisory for them):

  * CVE-2002-1364 (BugTraq ID 6166) talks about a buffer overflow in
the get_origin function which allows attackers to execute arbitrary
code via long WHOIS responses.

  * CVE-2002-1051 (BugTraq ID 4956) talks about a format string
vulnerability that allows local users to execute arbitrary code via
the -T (terminator) command line argument.

  * CVE-2002-1386 talks about a buffer overflow that may allow local
users to execute arbitrary code via a long hostname argument.

  * CVE-2002-1387 talks about the spray mode that may allow local users
to overwrite arbitrary memory locations.

Fortunately, the Debian package drops privileges quite early after
startup, so those problems are not likely to result in an exploit on a
Debian machine.

For the current stable distribution (woody) the above problem has been
fixed in version 6.1.1-1.2.

For the old stable distribution (potato) the above problem has been
fixed in version 6.0-2.2.

For the unstable distribution (sid) these problems have been fixed in
version 6.3.0-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your traceroute-nanog package.");
  script_tag(name:"summary", value:"The remote host is missing an update to traceroute-nanog
announced via advisory DSA 254-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"traceroute-nanog", ver:"6.0-2.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"traceroute-nanog", ver:"6.1.1-1.2", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

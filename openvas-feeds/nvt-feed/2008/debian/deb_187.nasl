# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53735");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2001-0131", "CVE-2002-0839", "CVE-2002-0840", "CVE-2002-0843", "CVE-2002-1233");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 187-1 (apache)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(2\.2|3\.0)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20187-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5847");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5884");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5887");
  script_tag(name:"insight", value:"According to David Wagner, iDEFENSE and the Apache HTTP Server
Project, several remotely exploitable vulnerabilities have been found
in the Apache package, a commonly used webserver.  These
vulnerabilities could allow an attacker to enact a denial of service
against a server or execute a cross scripting attack.  The Common
Vulnerabilities and Exposures (CVE) project identified the following
vulnerabilities:

1. CVE-2002-0839: A vulnerability exists on platforms using System V
shared memory based scoreboards.  This vulnerability allows an
attacker who can execute under the Apache UID to exploit the Apache
shared memory scoreboard format and send a signal to any process as
root or cause a local denial of service attack.

2. CVE-2002-0840: Apache is susceptible to a cross site scripting
vulnerability in the default 404 page of any web server hosted on a
domain that allows wildcard DNS lookups.

3. CVE-2002-0843: There were some possible overflows in the utility
ApacheBench (ab) which could be exploited by a malicious server.

4. CVE-2002-1233: A race condition in the htpasswd and htdigest
program enables a malicious local user to read or even modify the
contents of a password file or easily create and overwrite files as
the user running the htpasswd (or htdigest respectively) program.

5. CVE-2001-0131: htpasswd and htdigest in Apache 2.0a9, 1.3.14, and
others allows local users to overwrite arbitrary files via a
symlink attack.

This is the same vulnerability as CVE-2002-1233, which was fixed in
potato already but got lost later and was never applied upstream.

5. NO-CAN: Several buffer overflows have been found in the ApacheBench
(ab) utility that could be exploited by a remote server returning
very long strings.

These problems have been fixed in version 1.3.26-0woody3 for the
current stable distribution (woody) and in 1.3.9-14.3 for the old
stable distribution (potato).  Corrected packages for the unstable
distribution (sid) are expected soon.");

  script_tag(name:"solution", value:"We recommend that you upgrade your Apache package immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to apache
announced via advisory DSA 187-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"apache-doc", ver:"1.3.9-14.3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache", ver:"1.3.9-14.3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache-common", ver:"1.3.9-14.3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache-dev", ver:"1.3.9-14.3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache-doc", ver:"1.3.26-0woody3", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache", ver:"1.3.26-0woody3", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache-common", ver:"1.3.26-0woody3", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache-dev", ver:"1.3.26-0woody3", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

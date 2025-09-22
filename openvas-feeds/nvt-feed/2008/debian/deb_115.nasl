# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53395");
  script_cve_id("CVE-2002-0081");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 115-1 (php3, php4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20115-1");
  script_tag(name:"insight", value:"Stefan Esser, who is also a member of the PHP team, found several
flaws in the way PHP handles multipart/form-data POST requests (as
described in RFC1867) known as POST fileuploads.  Each of the flaws
could allow an attacker to execute arbitrary code on the victim's
system.

For PHP3 flaws contain a broken boundary check and an arbitrary heap
overflow.  For PHP4 they consist of a broken boundary check and a heap
off by one error.

For the stable release of Debian these problems are fixed in version
3.0.18-0potato1.1 of PHP3 and version 4.0.3pl1-0potato3 of PHP4.

For the unstable and testing release of Debian these problems are
fixed in version 3.0.18-22 of PHP3 and version 4.1.2-1 of PHP4.

There is no PHP4 in the stable and unstable distribution for the arm
architecture due to a compiler error.");

  script_tag(name:"solution", value:"We recommend that you upgrade your php packages immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to php3, php4
announced via advisory DSA 115-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"php3-doc", ver:"3.0.18-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-dev", ver:"4.0.3pl1-0potato3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php3-cgi-gd", ver:"3.0.18-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php3-cgi-imap", ver:"3.0.18-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php3-cgi-ldap", ver:"3.0.18-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php3-cgi-magick", ver:"3.0.18-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php3-cgi-mhash", ver:"3.0.18-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php3-cgi-mysql", ver:"3.0.18-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php3-cgi-pgsql", ver:"3.0.18-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php3-cgi-snmp", ver:"3.0.18-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php3-cgi-xml", ver:"3.0.18-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php3-cgi", ver:"3.0.18-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php3-dev", ver:"3.0.18-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php3-gd", ver:"3.0.18-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php3-imap", ver:"3.0.18-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php3-ldap", ver:"3.0.18-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php3-magick", ver:"3.0.18-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php3-mhash", ver:"3.0.18-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php3-mysql", ver:"3.0.18-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php3-pgsql", ver:"3.0.18-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php3-snmp", ver:"3.0.18-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php3-xml", ver:"3.0.18-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php3", ver:"3.0.18-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-cgi-gd", ver:"4.0.3pl1-0potato3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4", ver:"4.0.3pl1-0potato3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-cgi-imap", ver:"4.0.3pl1-0potato3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-cgi-ldap", ver:"4.0.3pl1-0potato3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-cgi-mhash", ver:"4.0.3pl1-0potato3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-cgi-mysql", ver:"4.0.3pl1-0potato3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-cgi-pgsql", ver:"4.0.3pl1-0potato3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-cgi-snmp", ver:"4.0.3pl1-0potato3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-cgi-xml", ver:"4.0.3pl1-0potato3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-cgi", ver:"4.0.3pl1-0potato3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-gd", ver:"4.0.3pl1-0potato3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-imap", ver:"4.0.3pl1-0potato3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-ldap", ver:"4.0.3pl1-0potato3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-mhash", ver:"4.0.3pl1-0potato3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-mysql", ver:"4.0.3pl1-0potato3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-pgsql", ver:"4.0.3pl1-0potato3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-snmp", ver:"4.0.3pl1-0potato3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-xml", ver:"4.0.3pl1-0potato3", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53783");
  script_cve_id("CVE-2001-0108", "CVE-2001-1385");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Debian Security Advisory DSA 020-1 (php4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20020-1");
  script_tag(name:"insight", value:"The Zend people have found a vulnerability in older versions of PHP4
(the original advisory speaks of 4.0.4 while the bugs are present in
4.0.3 as well).  It is possible to specify PHP directives on a
per-directory basis which leads to a remote attacker crafting an HTTP
request that would cause the next page to be served with the wrong
values for these directives.  Also even if PHP is installed, it can be
activated and deactivated on a per-directory or per-virtual host basis
using the 'engine=on' or 'engine=off' directive.  This setting can be
leaked to other virtual hosts on the same machine, effectively
disabling PHP for those hosts and resulting in PHP source code being
sent to the client instead of being executed on the server.

We recommend you upgrade your php4 packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to php4
announced via advisory DSA 020-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"php4-cgi-gd", ver:"4.0.3pl1-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-cgi-imap", ver:"4.0.3pl1-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-cgi-ldap", ver:"4.0.3pl1-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-cgi-mhash", ver:"4.0.3pl1-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-cgi-mysql", ver:"4.0.3pl1-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-cgi-pgsql", ver:"4.0.3pl1-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-cgi-snmp", ver:"4.0.3pl1-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-cgi-xml", ver:"4.0.3pl1-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-cgi", ver:"4.0.3pl1-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-gd", ver:"4.0.3pl1-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-imap", ver:"4.0.3pl1-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-ldap", ver:"4.0.3pl1-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-mhash", ver:"4.0.3pl1-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-mysql", ver:"4.0.3pl1-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-pgsql", ver:"4.0.3pl1-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-snmp", ver:"4.0.3pl1-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-xml", ver:"4.0.3pl1-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4", ver:"4.0.3pl1-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-dev", ver:"4.0.3pl1-0potato1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

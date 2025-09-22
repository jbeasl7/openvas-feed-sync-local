# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53211");
  script_cve_id("CVE-2004-0547");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:45:44 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Debian Security Advisory DSA 516-1 (postgresql)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20516-1");
  script_tag(name:"insight", value:"A buffer overflow has been discovered in the ODBC driver of PostgreSQL,
an object-relational SQL database, descended from POSTGRES.  It possible
to exploit this problem and crash the surrounding application.  Hence, a
PHP script using php4-odbc can be utilised to crash the surrounding
Apache webserver.  Other parts of postgresql are not affected.

For the stable distribution (woody) this problem has been fixed in
version 7.2.1-2woody5.

For the unstable distribution (sid) this problem has been fixed in
version 07.03.0200-3.");

  script_tag(name:"solution", value:"We recommend that you upgrade your postgresql and related package.");
  script_tag(name:"summary", value:"The remote host is missing an update to postgresql
announced via advisory DSA 516-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"postgresql-doc", ver:"7.2.1-2woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libecpg3", ver:"7.2.1-2woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpgperl", ver:"7.2.1-2woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpgsql2", ver:"7.2.1-2woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpgtcl", ver:"7.2.1-2woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"odbc-postgresql", ver:"7.2.1-2woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pgaccess", ver:"7.2.1-2woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql", ver:"7.2.1-2woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-client", ver:"7.2.1-2woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-contrib", ver:"7.2.1-2woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-dev", ver:"7.2.1-2woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-pygresql", ver:"7.2.1-2woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

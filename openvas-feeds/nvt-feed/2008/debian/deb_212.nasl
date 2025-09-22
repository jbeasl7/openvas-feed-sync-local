# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53585");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-1373", "CVE-2002-1374", "CVE-2002-1375", "CVE-2002-1376");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 212-1 (mysql)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(2\.2|3\.0)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20212-1");
  script_tag(name:"insight", value:"While performing an audit of MySQL e-matters found several problems:

  * signed/unsigned problem in COM_TABLE_DUMP
Two sizes were taken as signed integers from a request and then cast
to unsigned integers without checking for negative numbers. Since the
resulting numbers where used for a memcpy() operation this could lead
to memory corruption.

  * Password length handling in COM_CHANGE_USER
When re-authenticating to a different user MySQL did not perform
all checks that are performed on initial authentication. This created
two problems:

  * it allowed for single-character password brute forcing (as was fixed in
February 2000 for initial login) which could be used by a normal user to
gain root privileges to the database

  * it was possible to overflow the password buffer and force the server
to execute arbitrary code

  * read_rows() overflow in libmysqlclient
When processing the rows returned by a SQL server there was no check
for overly large rows or terminating NUL characters. This can be used
to exploit SQL clients if they connect to a compromised MySQL server.

  * read_one_row() overflow in libmysqlclient
When processing a row as returned by a SQL server the returned field
sizes were not verified. This can be used to exploit SQL clients if they
connect to a compromised MySQL server.

For Debian GNU/Linux 3.0/woody this has been fixed in version 3.23.49-8.2
and version 3.22.32-6.3 for Debian GNU/Linux 2.2/potato.");

  script_tag(name:"solution", value:"We recommend that you upgrade your mysql packages as soon as possible.");
  script_tag(name:"summary", value:"The remote host is missing an update to mysql
announced via advisory DSA 212-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"mysql-doc", ver:"3.22.32-6.3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mysql-server", ver:"3.22.32-6.3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mysql-client", ver:"3.22.32-6.3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mysql-doc", ver:"3.23.49-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mysql-server", ver:"3.23.49-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mysql-client", ver:"3.23.49-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mysql-common", ver:"3.23.49-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmysqlclient10-dev", ver:"3.23.49-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmysqlclient10", ver:"3.23.49-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

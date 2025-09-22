# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53755");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2004-0381", "CVE-2004-0388");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Debian Security Advisory DSA 483-1 (mysql)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20483-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9976");
  script_tag(name:"insight", value:"Two vulnerabilities have been discovered in mysql, a common database
system.  Two scripts contained in the package don't create temporary
files in a secure fashion.  This could allow a local attacker to
overwrite files with the privileges of the user invoking the MySQL
server, which is often the root user.  The Common Vulnerabilities and
Exposures identifies the following problems:

CVE-2004-0381

The script mysqlbug in MySQL allows local users to overwrite
arbitrary files via a symlink attack.

CVE-2004-0388

The script mysqld_multi in MySQL allows local users to overwrite
arbitrary files via a symlink attack.

For the stable distribution (woody) these problems have been fixed in
version 3.23.49-8.6.

For the unstable distribution (sid) these problems will be fixed in
version 4.0.18-6 of mysql-dfsg.");

  script_tag(name:"solution", value:"We recommend that you upgrade your mysql, mysql-dfsg and related");
  script_tag(name:"summary", value:"The remote host is missing an update to mysql
announced via advisory DSA 483-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"mysql-common", ver:"3.23.49-8.6", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmysqlclient10", ver:"3.23.49-8.6", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmysqlclient10-dev", ver:"3.23.49-8.6", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mysql-client", ver:"3.23.49-8.6", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mysql-server", ver:"3.23.49-8.6", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

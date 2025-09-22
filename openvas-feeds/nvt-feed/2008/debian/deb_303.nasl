# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53595");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:36:24 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0073", "CVE-2003-0150");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 303-1 (mysql)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.0|2\.2)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20303-1");
  script_tag(name:"insight", value:"CVE-2003-0073: The mysql package contains a bug whereby dynamically
allocated memory is freed more than once, which could be deliberately
triggered by an attacker to cause a crash, resulting in a denial of
service condition.  In order to exploit this vulnerability, a valid
username and password combination for access to the MySQL server is
required.

CVE-2003-0150: The mysql package contains a bug whereby a malicious
user, granted certain permissions within mysql, could create a
configuration file which would cause the mysql server to run as root,
or any other user, rather than the mysql user.

For the stable distribution (woody) both problems have been fixed in
version 3.23.49-8.4.

The old stable distribution (potato) is only affected by
CVE-2003-0150, and this has been fixed in version 3.22.32-6.4.

For the unstable distribution (sid), CVE-2003-0073 was fixed in
version 4.0.12-2, and CVE-2003-0150 will be fixed soon.

We recommend that you update your mysql package.");
  script_tag(name:"summary", value:"The remote host is missing an update to mysql
announced via advisory DSA 303-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"mysql-common", ver:"3.23.49-8.4", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mysql-doc", ver:"3.23.49-8.4", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmysqlclient10", ver:"3.23.49-8.4", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmysqlclient10-dev", ver:"3.23.49-8.4", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mysql-client", ver:"3.23.49-8.4", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mysql-server", ver:"3.23.49-8.4", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mysql-doc", ver:"3.22.32-6.4", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mysql-client", ver:"3.22.32-6.4", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mysql-server", ver:"3.22.32-6.4", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

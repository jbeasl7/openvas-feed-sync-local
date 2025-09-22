# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53153");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2004-0110");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 455-1 (libxml, libxml2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20455-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9718");
  script_tag(name:"insight", value:"libxml2 is a library for manipulating XML files.

Yuuichi Teranishi discovered a flaw in libxml, the GNOME XML library.
When fetching a remote resource via FTP or HTTP, the library uses
special parsing routines which can overflow a buffer if passed a very
long URL.  If an attacker is able to find an application using libxml1
or libxml2 that parses remote resources and allows the attacker to
craft the URL, then this flaw could be used to execute arbitrary code.

For the stable distribution (woody) this problem has been fixed in
version 1.8.17-2woody1 of libxml and version 2.4.19-4woody1 of libxml2.

For the unstable distribution (sid) this problem has been fixed in
version 1.8.17-5 of libxml and version 2.6.6-1 of libxml2.");

  script_tag(name:"solution", value:"We recommend that you upgrade your libxml1 and libxml2 packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to libxml, libxml2
announced via advisory DSA 455-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libxml-dev", ver:"1.8.17-2woody1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxml1", ver:"1.8.17-2woody1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxml2", ver:"2.4.19-4woody1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxml2-dev", ver:"2.4.19-4woody1", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

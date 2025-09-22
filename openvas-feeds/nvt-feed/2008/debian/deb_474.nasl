# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53172");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2004-0189");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 474-1 (squid)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20474-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9778");
  script_tag(name:"insight", value:"A vulnerability was discovered in squid, an Internet object cache,
whereby access control lists based on URLs could be bypassed
(CVE-2004-0189).  Two other bugs were also fixed with patches
squid-2.4.STABLE7-url_escape.patch (a buffer overrun which does not
appear to be exploitable) and squid-2.4.STABLE7-url_port.patch (a
potential denial of service).

For the stable distribution (woody) these problems have been fixed in
version 2.4.6-2woody2.

For the unstable distribution (sid) these problems have been fixed in
version 2.5.5-1.

We recommend that you update your squid package.");
  script_tag(name:"summary", value:"The remote host is missing an update to squid
announced via advisory DSA 474-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"squid", ver:"2.4.6-2woody2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squid-cgi", ver:"2.4.6-2woody2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squidclient", ver:"2.4.6-2woody2", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53715");
  script_version("2024-06-26T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"creation_date", value:"2008-01-17 22:56:38 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2004-0999", "CVE-2004-1095");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 608-1 (zgv)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20608-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11556");
  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in zgv, an SVGAlib
graphics viewer for the i386 architecture.  The Common Vulnerabilities
and Exposures Project identifies the following problems:

CVE-2004-1095

Luke Macken and infamous41md independently discovered multiple
integer overflows in zgv.  Remote exploitation of an integer
overflow vulnerability could allow the execution of arbitrary
code.

CVE-2004-0999

Mikulas Patocka discovered that malicious multiple-image (e.g.
animated) GIF images can cause a segmentation fault in zgv.

For the stable distribution (woody) these problems have been fixed in
version 5.5-3woody1.

For the unstable distribution (sid) these problems will be fixed soon.");

  script_tag(name:"solution", value:"We recommend that you upgrade your zgv package immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to zgv
announced via advisory DSA 608-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"zgv", ver:"5.5-3woody2", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53453");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-1363");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 213-1 (libpng, libpng3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(2\.2|3\.0)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20213-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6431");
  script_tag(name:"insight", value:"Glenn Randers-Pehrson discovered a problem in connection with 16-bit
samples from libpng, an interface for reading and writing PNG
(Portable Network Graphics) format files.  The starting offsets for
the loops are calculated incorrectly which causes a buffer overrun
beyond the beginning of the row buffer.

For the current stable distribution (woody) this problem has been
fixed in version 1.0.12-3.woody.3 for libpng and in version
1.2.1-1.1.woody.3 for libpng3.

For the old stable distribution (potato) this problem has been fixed
in version 1.0.5-1.1 for libpng.  There are no other libpng packages.

For the unstable distribution (sid) this problem has been fixed in
version 1.0.12-7 for libpng and in version 1.2.5-8 for libpng3.");

  script_tag(name:"solution", value:"We recommend that you upgrade your libpng packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to libpng, libpng3
announced via advisory DSA 213-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libpng2", ver:"1.0.5-1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpng2-dev", ver:"1.0.5-1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpng2", ver:"1.0.12-3.woody.3", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpng2-dev", ver:"1.0.12-3.woody.3", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpng-dev", ver:"1.2.1-1.1.woody.3", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpng3", ver:"1.2.1-1.1.woody.3", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

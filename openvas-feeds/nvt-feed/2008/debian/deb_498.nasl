# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53188");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2004-0421");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Debian Security Advisory DSA 498-1 (libpng, libpng3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20498-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10244");
  script_tag(name:"insight", value:"Steve Grubb discovered a problem in the Portable Network Graphics
library libpng which is utilised in several applications.  When
processing a broken PNG image, the error handling routine will access
memory that is out of bounds when creating an error message.
Depending on machine architecture, bounds checking and other
protective measures, this problem could cause the program to crash if
a defective or intentionally prepared PNG image file is handled by
libpng.

This could be used as a denial of service attack against various
programs that link against this library.  The following commands will
show you which packages utilise this library and whose programs should
probably restarted after an upgrade:

apt-cache showpkg libpng2
apt-cache showpkg libpng3

The following security matrix explains which package versions will
contain a correction.

Package      stable (woody)          unstable (sid)
libpng     1.0.12-3.woody.5          1.0.15-5
libpng3    1.2.1-1.1.woody.5         1.2.5.0-6");

  script_tag(name:"solution", value:"We recommend that you upgrade your libpng and related packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to libpng, libpng3
announced via advisory DSA 498-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libpng2", ver:"1.0.12-3.woody.5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpng2-dev", ver:"1.0.12-3.woody.5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpng-dev", ver:"1.2.1-1.1.woody.5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpng3", ver:"1.2.1-1.1.woody.5", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

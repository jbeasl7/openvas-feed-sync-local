# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53450");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-0836");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 207-1 (tetex-bin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(2\.2|3\.0)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20207-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5978");
  script_tag(name:"insight", value:"The SuSE security team discovered a vulnerability in kpathsea library
(libkpathsea) which is used by xdvi and dvips.  Both programs call the
system() function insecurely, which allows a remote attacker to
execute arbitrary commands via cleverly crafted DVI files.

If dvips is used in a print filter, this allows a local or remote
attacker with print permission execute arbitrary code as the printer
user (usually lp).

This problem has been fixed in version 1.0.7+20011202-7.1for the
current stable distribution (woody), in version 1.0.6-7.3 for the old
stable distribution (potato) and in version 1.0.7+20021025-4 for the
unstable distribution (sid).  xdvik-ja and dvipsk-ja are vulnerable as
well, but link to the kpathsea library dynamically and will
automatically be fixed after a new libkpathsea is installed.");

  script_tag(name:"solution", value:"We recommend that you upgrade your tetex-lib package immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to tetex-bin
announced via advisory DSA 207-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"tetex-bin", ver:"1.0.6-7.3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tetex-dev", ver:"1.0.6-7.3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tetex-lib", ver:"1.0.6-7.3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkpathsea-dev", ver:"1.0.7+20011202-7.1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkpathsea3", ver:"1.0.7+20011202-7.1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tetex-bin", ver:"1.0.7+20011202-7.1", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

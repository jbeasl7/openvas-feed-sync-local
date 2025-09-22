# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53765");
  script_cve_id("CVE-2001-1562");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 085-1 (nvi, nvi-m17n)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20085-1");
  script_tag(name:"insight", value:"Takeshi Uno found a very stupid format string vulnerability in all
versions of nvi (in both, the plain and the multilingualized version).
When a filename is saved, it ought to get displayed on the screen.
The routine handling this didn't escape format strings.

This problem has been fixed in version 1.79-16a.1 for nvi and
1.79+19991117-2.3 for nvi-m17n for the stable Debian GNU/Linux 2.2.

Even if we don't believe that this could lead into somebody gaining
access of another users account if he hasn't lost his brain, we
recommend that you upgrade your nvi packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to nvi, nvi-m17n
announced via advisory DSA 085-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"nvi-m17n-common", ver:"1.79+19991117-2.3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nvi-m17n-canna", ver:"1.79+19991117-2.3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nvi-m17n", ver:"1.79+19991117-2.3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nvi", ver:"1.79-16a.1", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53447");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-1281", "CVE-2002-1282");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 204-1 (kdelibs)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20204-1");
  script_tag(name:"insight", value:"The KDE team has discovered a vulnerability in the support for various
network protocols via the KIO The implementation of the rlogin and
protocol allows a carefully crafted URL in an HTML page, HTML email or
other KIO-enabled application to execute arbitrary commands on the
system using the victim's account on the vulnerable machine.

This problem has been fixed by disabling rlogin and telnet in version
2.2.2-13.woody.5 for the current stable distribution (woody) and in
version 2.2.2-14.1 for the unstable distribution (sid).  The old
stable distribution (potato) is not affected since it doesn't contain
KDE.

This problem has been fixed by disabling rlogin and telnet in version
2.2.2-13.woody.5 for the current stable distribution (woody).  The old
stable distribution (potato) is not affected since it doesn't contain
KDE.  A correction for the package in the unstable distribution (sid)
is not yet available.");

  script_tag(name:"solution", value:"We recommend that you upgrade your kdelibs3 package immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to kdelibs
announced via advisory DSA 204-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"kdelibs3-doc", ver:"2.2.2-13.woody.5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kdelibs-dev", ver:"2.2.2-13.woody.5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kdelibs3", ver:"2.2.2-13.woody.5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kdelibs3-bin", ver:"2.2.2-13.woody.5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kdelibs3-cups", ver:"2.2.2-13.woody.5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libarts", ver:"2.2.2-13.woody.5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libarts-alsa", ver:"2.2.2-13.woody.5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libarts-dev", ver:"2.2.2-13.woody.5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkmid", ver:"2.2.2-13.woody.5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkmid-alsa", ver:"2.2.2-13.woody.5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkmid-dev", ver:"2.2.2-13.woody.5", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

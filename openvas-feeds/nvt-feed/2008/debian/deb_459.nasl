# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53157");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0592");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 459-1 (kdelibs, kdelibs-crypto)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20459-1");
  script_tag(name:"insight", value:"A vulnerability was discovered in KDE where the path restrictions on
cookies could be bypassed using encoded relative path components
(e.g., /../).  This means that a cookie which should only be sent by
the browser to an application running at /app1, the browser could
inadvertently include it with a request sent to /app2 on the same
server.

For the current stable distribution (woody) this problem has been
fixed in kdelibs version 4:2.2.2-6woody3 and kdelibs-crypto version
4:2.2.2-13.woody.9.

For the unstable distribution (sid) this problem was fixed in kdelibs
version 4:3.1.3-1.

We recommend that you update your kdelibs and kdelibs-crypto packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to kdelibs, kdelibs-crypto
announced via advisory DSA 459-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"kdelibs3-doc", ver:"2.2.2-13.woody.9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kdelibs-dev", ver:"2.2.2-13.woody.9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kdelibs3", ver:"2.2.2-13.woody.9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kdelibs3-bin", ver:"2.2.2-13.woody.9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kdelibs3-cups", ver:"2.2.2-13.woody.9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libarts", ver:"2.2.2-13.woody.9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libarts-alsa", ver:"2.2.2-13.woody.9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libarts-dev", ver:"2.2.2-13.woody.9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkmid", ver:"2.2.2-13.woody.9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkmid-alsa", ver:"2.2.2-13.woody.9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkmid-dev", ver:"2.2.2-13.woody.9", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kdelibs3-crypto", ver:"2.2.2-6woody3", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

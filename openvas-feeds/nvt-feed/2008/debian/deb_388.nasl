# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53672");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:36:24 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0690", "CVE-2003-0692");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 388-1 (kdebase)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20388-1");
  script_xref(name:"URL", value:"http://www.kde.org/info/security/advisory-20030916-1.txt");
  script_tag(name:"insight", value:"Two vulnerabilities were discovered in kdebase:

  - CVE-2003-0690

KDM in KDE 3.1.3 and earlier does not verify whether the pam_setcred
function call succeeds, which may allow attackers to gain root
privileges by triggering error conditions within PAM modules, as
demonstrated in certain configurations of the MIT pam_krb5 module.

  - CVE-2003-0692

KDM in KDE 3.1.3 and earlier uses a weak session cookie generation
algorithm that does not provide 128 bits of entropy, which allows
attackers to guess session cookies via brute force methods and gain
access to the user session.

These vulnerabilities are described in the referenced security
advisory from KDE.

For the current stable distribution (woody) these problems have been
fixed in version 4:2.2.2-14.7.

For the unstable distribution (sid) these problems will be fixed soon.

We recommend that you update your kdebase package.");
  script_tag(name:"summary", value:"The remote host is missing an update to kdebase
announced via advisory DSA 388-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"kdebase-doc", ver:"2.2.2-14.7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kdewallpapers", ver:"2.2.2-14.7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kate", ver:"2.2.2-14.7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kdebase", ver:"2.2.2-14.7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kdebase-audiolibs", ver:"2.2.2-14.7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kdebase-dev", ver:"2.2.2-14.7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kdebase-libs", ver:"2.2.2-14.7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kdm", ver:"2.2.2-14.7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"konqueror", ver:"2.2.2-14.7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"konsole", ver:"2.2.2-14.7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kscreensaver", ver:"2.2.2-14.7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkonq-dev", ver:"2.2.2-14.7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkonq3", ver:"2.2.2-14.7", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

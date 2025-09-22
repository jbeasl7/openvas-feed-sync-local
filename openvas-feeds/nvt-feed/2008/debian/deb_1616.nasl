# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61369");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-08-15 15:52:52 +0200 (Fri, 15 Aug 2008)");
  script_cve_id("CVE-2008-2713");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Debian Security Advisory DSA 1616-2 (clamav)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201616-2");
  script_tag(name:"insight", value:"This update corrects a packaging and build error in the packages
released in DSA-1616-1.  Those packages, while functional, did not
actually apply the fix intended.  This update restores the fix
to the package build. No other changes are introduced.  For
reference, the text of the original advisory follows.

Damian Put discovered a vulnerability in the ClamAV anti-virus
toolkit's parsing of Petite-packed Win32 executables.  The weakness
leads to an invalid memory access, and could enable an attacker to
crash clamav by supplying a maliciously crafted Petite-compressed
binary for scanning.  In some configurations, such as when clamav
is used in combination with mail servers, this could cause a system
to fail open, facilitating a follow-on viral attack.

The Common Vulnerabilities and Exposures project identifies this
weakness as CVE-2008-2713.

For the stable distribution (etch), this problem has been fixed in
version 0.90.1dfsg-3.1+etch14.  For the unstable distribution (sid),
the problem has been fixed in version 0.93.1.dfsg-1.1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your clamav packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to clamav
announced via advisory DSA 1616-2.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"clamav-docs", ver:"0.90.1dfsg-3.1+etch14", rls:"DEB4")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"clamav-testfiles", ver:"0.90.1dfsg-3.1+etch14", rls:"DEB4")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"clamav-base", ver:"0.90.1dfsg-3.1+etch14", rls:"DEB4")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"clamav-daemon", ver:"0.90.1dfsg-3.1+etch14", rls:"DEB4")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"clamav-freshclam", ver:"0.90.1dfsg-3.1+etch14", rls:"DEB4")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"clamav-dbg", ver:"0.90.1dfsg-3.1+etch14", rls:"DEB4")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"clamav", ver:"0.90.1dfsg-3.1+etch14", rls:"DEB4")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libclamav-dev", ver:"0.90.1dfsg-3.1+etch14", rls:"DEB4")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libclamav2", ver:"0.90.1dfsg-3.1+etch14", rls:"DEB4")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"clamav-milter", ver:"0.90.1dfsg-3.1+etch14", rls:"DEB4")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

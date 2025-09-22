# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53451");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-1323");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 208-1 (perl, perl-5.004, perl-5.005)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(2\.2|3\.0)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20208-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6111");
  script_tag(name:"insight", value:"A security hole has been discovered in Safe.pm which is used in all
versions of Perl.  The Safe extension module allows the creation of
compartments in which perl code can be evaluated in a new namespace
and the code evaluated in the compartment cannot refer to variables
outside this namespace.  However, when a Safe compartment has already
been used, there's no guarantee that it is Safe any longer, because
there's a way for code to be executed within the Safe compartment to
alter its operation mask.  Thus, programs that use a Safe compartment
only once aren't affected by this bug.

This problem has been fixed in version 5.6.1-8.2 for the current
stable distribution (woody), in version 5.004.05-6.2 and 5.005.03-7.2
for the old stable distribution (potato) and in version 5.8.0-14 for
the unstable distribution (sid).");

  script_tag(name:"solution", value:"We recommend that you upgrade your Perl packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to perl, perl-5.004, perl-5.005
announced via advisory DSA 208-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"perl-5.004-doc", ver:"5.004.05-6.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-5.005-doc", ver:"5.005.03-7.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-5.004", ver:"5.004.05-6.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-5.004-base", ver:"5.004.05-6.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-5.004-debug", ver:"5.004.05-6.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-5.004-suid", ver:"5.004.05-6.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-5.005", ver:"5.005.03-7.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-5.005-base", ver:"5.005.03-7.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-5.005-debug", ver:"5.005.03-7.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-5.005-suid", ver:"5.005.03-7.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-5.005-thread", ver:"5.005.03-7.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcgi-fast-perl", ver:"5.6.1-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-doc", ver:"5.6.1-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-modules", ver:"5.6.1-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libperl-dev", ver:"5.6.1-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libperl5.6", ver:"5.6.1-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl", ver:"5.6.1-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-base", ver:"5.6.1-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-debug", ver:"5.6.1-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"perl-suid", ver:"5.6.1-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

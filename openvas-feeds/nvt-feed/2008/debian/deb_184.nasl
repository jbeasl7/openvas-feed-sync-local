# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53434");
  script_cve_id("CVE-2002-1235");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 184-1 (krb4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(2\.2|3\.0)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20184-1");
  script_tag(name:"insight", value:"Tom Yu and Sam Hartman of MIT discovered another stack buffer overflow
in the kadm_ser_wrap_in function in the Kerberos v4 administration
server.  This kadmind bug has a working exploit code circulating,
hence it is considered serious.

This problem has been fixed in version 1.1-8-2.2 for the current
stable distribution (woody), in version 1.0-2.2 for the old stable
distribution (potato) and in version 1.1-11-8 for the unstable
distribution (sid).");

  script_tag(name:"solution", value:"We recommend that you upgrade your krb4 packages immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to krb4
announced via advisory DSA 184-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"kerberos4kth-clients", ver:"1.0-2.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kerberos4kth-dev", ver:"1.0-2.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kerberos4kth-kdc", ver:"1.0-2.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kerberos4kth-services", ver:"1.0-2.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kerberos4kth-user", ver:"1.0-2.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kerberos4kth-x11", ver:"1.0-2.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kerberos4kth1", ver:"1.0-2.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kerberos4kth-docs", ver:"1.1-8-2.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kerberos4kth-services", ver:"1.1-8-2.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kerberos4kth-user", ver:"1.1-8-2.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kerberos4kth-x11", ver:"1.1-8-2.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kerberos4kth1", ver:"1.1-8-2.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kerberos4kth-clients", ver:"1.1-8-2.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kerberos4kth-clients-x", ver:"1.1-8-2.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kerberos4kth-dev", ver:"1.1-8-2.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kerberos4kth-dev-common", ver:"1.1-8-2.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kerberos4kth-kdc", ver:"1.1-8-2.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kerberos4kth-kip", ver:"1.1-8-2.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kerberos4kth-servers", ver:"1.1-8-2.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kerberos4kth-servers-x", ver:"1.1-8-2.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libacl1-kerberos4kth", ver:"1.1-8-2.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkadm1-kerberos4kth", ver:"1.1-8-2.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkdb-1-kerberos4kth", ver:"1.1-8-2.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb-1-kerberos4kth", ver:"1.1-8-2.2", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

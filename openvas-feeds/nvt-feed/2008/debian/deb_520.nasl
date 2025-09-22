# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53210");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:45:44 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2004-0523");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 520-1 (krb5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20520-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10448");
  script_tag(name:"insight", value:"In their advisory MITKRB5-SA-2004-001, the MIT Kerberos announced the
existence of buffer overflow vulnerabilities in the
krb5_aname_to_localname function.  This function is only used if
aname_to_localname is enabled in the configuration (this is not
enabled by default).

For the current stable distribution (woody), this problem has been
fixed in version 1.2.4-5woody5.

For the unstable distribution (sid), this problem has been fixed in
version 1.3.3-2.

We recommend that you update your krb5 package.");
  script_tag(name:"summary", value:"The remote host is missing an update to krb5
announced via advisory DSA 520-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"krb5-doc", ver:"1.2.4-5woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.2.4-5woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-clients", ver:"1.2.4-5woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-ftpd", ver:"1.2.4-5woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.2.4-5woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-rsh-server", ver:"1.2.4-5woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-telnetd", ver:"1.2.4-5woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-user", ver:"1.2.4-5woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkadm55", ver:"1.2.4-5woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.2.4-5woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb53", ver:"1.2.4-5woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

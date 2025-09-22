# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53739");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-0379");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 215-1 (cyrus-imapd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(2\.2|3\.0)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20215-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4713");
  script_tag(name:"insight", value:"Timo Sirainen discovered a buffer overflow in the Cyrus IMAP server,
which could be exploited by a remote attacker prior to logging in.  A
malicious user could craft a request to run commands on the server under
the UID and GID of the cyrus server.

For the current stable distribution (woody) this problem has been
fixed in version 1.5.19-9.1.

For the old stable distribution (potato) this problem has been fixed
in version 1.5.19-2.2.

For the current unstable distribution (sid) this problem has been
fixed in version 1.5.19-9.10.  The cyrus21-imapd packages are not
vulnerable");

  script_tag(name:"solution", value:"We recommend that you upgrade your cyrus-imapd package.");
  script_tag(name:"summary", value:"The remote host is missing an update to cyrus-imapd
announced via advisory DSA 215-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"cyrus-admin", ver:"1.5.19-2.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-common", ver:"1.5.19-2.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-dev", ver:"1.5.19-2.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-imapd", ver:"1.5.19-2.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-nntp", ver:"1.5.19-2.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-pop3d", ver:"1.5.19-2.2", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-admin", ver:"1.5.19-9.1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-common", ver:"1.5.19-9.1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-dev", ver:"1.5.19-9.1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-imapd", ver:"1.5.19-9.1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-nntp", ver:"1.5.19-9.1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cyrus-pop3d", ver:"1.5.19-9.1", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53677");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:36:24 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0543", "CVE-2003-0544");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Debian Security Advisory DSA 393-1 (openssl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20393-1");
  script_tag(name:"insight", value:"Dr. Stephen Henson (steve@openssl.org), using a test suite provided by
NISCC, discovered a number of errors in the OpenSSL
ASN1 code.  Combined with an error that causes the OpenSSL code to parse
client certificates even when it should not, these errors can cause a
denial of service (DoS) condition on a system using the OpenSSL code,
depending on how that code is used. For example, even though apache-ssl
and ssh link to OpenSSL libraries, they should not be affected by this
vulnerability. However, other SSL-enabled applications may be
vulnerable and an OpenSSL upgrade is recommended.

For the current stable distribution (woody) these problems have been
fixed in version 0.9.6c-2.woody.4

For the unstable distribution (sid) these problems have been fixed in
version 0.9.7c-1

We recommend that you update your openssl package. Note that you will
need to restart services which use the libssl library for this update
to take effect.");
  script_tag(name:"summary", value:"The remote host is missing an update to openssl
announced via advisory DSA 393-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"ssleay", ver:"0.9.6c-2.woody.4", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl-dev", ver:"0.9.6c-2.woody.4", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl0.9.6", ver:"0.9.6c-2.woody.4", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openssl", ver:"0.9.6c-2.woody.4", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53577");
  script_cve_id("CVE-2002-0082");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 120-1 (libapache-mod-ssl, apache-ssl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20120-1");
  script_tag(name:"insight", value:"Ed Moyle recently found a buffer overflow in Apache-SSL and mod_ssl.
With session caching enabled, mod_ssl will serialize SSL session
variables to store them for later use.  These variables were stored in
a buffer of a fixed size without proper boundary checks.

To exploit the overflow, the server must be configured to require client
certificates, and an attacker must obtain a carefully crafted client
certificate that has been signed by a Certificate Authority which is
trusted by the server. If these conditions are met, it would be possible
for an attacker to execute arbitrary code on the server.

This problem has been fixed in version 1.3.9.13-4 of Apache-SSL and
version 2.4.10-1.3.9-1potato1 of libapache-mod-ssl for the stable
Debian distribution as well as in version 1.3.23.1+1.47-1 of
Apache-SSL and version 2.8.7-1 of libapache-mod-ssl for the testing
and unstable distribution of Debian.");

  script_tag(name:"solution", value:"We recommend that you upgrade your Apache-SSL and mod_ssl packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to libapache-mod-ssl, apache-ssl
announced via advisory DSA 120-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libapache-mod-ssl-doc", ver:"2.4.10-1.3.9-1potato1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"apache-ssl", ver:"1.3.9.13-4", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache-mod-ssl", ver:"2.4.10-1.3.9-1potato1", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

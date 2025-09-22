# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53433");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-1157");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 181-1 (libapache-mod-ssl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(2\.2|3\.0)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20181-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6029");
  script_tag(name:"insight", value:"Joe Orton discovered a cross site scripting problem in mod_ssl, an
Apache module that adds Strong cryptography (i.e. HTTPS support) to
the webserver.  The module will return the server name unescaped in
the response to an HTTP request on an SSL port.

Like the other recent Apache XSS bugs, this only affects servers using
a combination of UseCanonicalName off (default in the Debian package
of Apache) and wildcard DNS.  This is very unlikely to happen, though.
Apache 2.0/mod_ssl is not vulnerable since it already escapes this
HTML.

With this setting turned on, whenever Apache needs to construct a
self-referencing URL (a URL that refers back to the server the
response is coming from) it will use ServerName and Port to form a
canonical name.  With this setting off, Apache will use the
hostname:port that the client supplied, when possible.  This also
affects SERVER_NAME and SERVER_PORT in CGI scripts.

This problem has been fixed in version 2.8.9-2.1 for the current
stable distribution (woody), in version 2.4.10-1.3.9-1potato4 for the
old stable distribution (potato) and version 2.8.9-2.3 for the
unstable distribution (sid).");

  script_tag(name:"solution", value:"We recommend that you upgrade your libapache-mod-ssl package.");
  script_tag(name:"summary", value:"The remote host is missing an update to libapache-mod-ssl
announced via advisory DSA 181-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libapache-mod-ssl-doc", ver:"2.4.10-1.3.9-1potato4", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache-mod-ssl", ver:"2.4.10-1.3.9-1potato4", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache-mod-ssl-doc", ver:"2.8.9-2.1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache-mod-ssl", ver:"2.8.9-2.1", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

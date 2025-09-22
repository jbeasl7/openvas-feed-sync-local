# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58826");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-2090", "CVE-2007-0450", "CVE-2007-1358");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("FreeBSD Ports: apache-tomcat");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_xref(name:"URL", value:"https://www.vuxml.org/freebsd/872623af-39ec-11dc-b8cc-000fea449b8a.html");
  script_tag(name:"insight", value:"The following packages are affected:

  apache-tomcat
   tomcat
   jakarta-tomcat

CVE-2005-2090
Jakarta Tomcat 5.0.19 (Coyote/1.1) and Tomcat 4.1.24 (Coyote/1.0)
allows remote attackers to poison the web cache, bypass web
application firewall protection, and conduct XSS attacks via an HTTP
request with both a 'Transfer-Encoding: chunked' header and a
Content-Length header, which causes Tomcat to incorrectly handle and
forward the body of the request in a way that causes the receiving
server to process it as a separate HTTP request, aka 'HTTP Request
Smuggling.'");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"apache-tomcat");
if(!isnull(bver) && revcomp(a:bver, b:"4.1.0")>=0 && revcomp(a:bver, b:"4.1.36")<0) {
  txt += 'Package apache-tomcat version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"6.0.0")>0 && revcomp(a:bver, b:"6.0.11")<0) {
  txt += 'Package apache-tomcat version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"tomcat");
if(!isnull(bver) && revcomp(a:bver, b:"5.0.0")>0 && revcomp(a:bver, b:"5.5.23")<0) {
  txt += 'Package tomcat version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"jakarta-tomcat");
if(!isnull(bver) && revcomp(a:bver, b:"4.0.0")>=0 && revcomp(a:bver, b:"4.1.0")<0) {
  txt += 'Package jakarta-tomcat version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"5.0.0")>0 && revcomp(a:bver, b:"5.5.23")<0) {
  txt += 'Package jakarta-tomcat version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}

# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52383");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0492");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: apache");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  apache
   apache13-ssl
   apache13-modssl
   apache13+ipv6
   apache13-modperl

CVE-2004-0492
Heap-based buffer overflow in proxy_util.c for mod_proxy in Apache
1.3.25 to 1.3.31 allows remote attackers to cause a denial of service
(process crash) and possibly execute arbitrary code via a negative
Content-Length HTTP header field, which causes a large amount of data
to be copied.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.guninski.com/modproxy1.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/ca6c8f35-0a5f-11d9-ad6f-00061bc2ad93.html");

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

bver = portver(pkg:"apache");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.31_1")<0) {
  txt += 'Package apache version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache13-ssl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.29.1.53_2")<=0) {
  txt += 'Package apache13-ssl version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache13-modssl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.31+2.8.18_4")<0) {
  txt += 'Package apache13-modssl version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache13+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.29_2")<=0) {
  txt += 'Package apache13+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache13-modperl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.31")<=0) {
  txt += 'Package apache13-modperl version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
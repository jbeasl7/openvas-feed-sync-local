# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52359");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0958");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("php -- php_variables memory disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  mod_php4-twig, php4-cgi, php4-cli, php4-dtc, php4-horde, php4-nms,
  php4, mod_php, mod_php4, php5, php5-cgi, php5-cli, mod_php5

The installed version of PHP suffers from a vulnerability
that allows remote attackers to read sensitive memory
contents.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=109527531130492");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11334");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/ad74a1bd-16d2-11d9-bc4a-000c41e2cdad.html");

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

bver = portver(pkg:"mod_php4-twig");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.8_2")<=0) {
  txt += 'Package mod_php4-twig version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php4-cgi");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.8_2")<=0) {
  txt += 'Package php4-cgi version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php4-cli");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.8_2")<=0) {
  txt += 'Package php4-cli version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php4-dtc");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.8_2")<=0) {
  txt += 'Package php4-dtc version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php4-horde");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.8_2")<=0) {
  txt += 'Package php4-horde version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php4-nms");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.8_2")<=0) {
  txt += 'Package php4-nms version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php4");
if(!isnull(bver) && revcomp(a:bver, b:"4.3.8_2")<=0) {
  txt += 'Package php4 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mod_php");
if(!isnull(bver) && revcomp(a:bver, b:"4")>=0 && revcomp(a:bver, b:"4.3.8_2,1")<=0) {
  txt += 'Package mod_php version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mod_php4");
if(!isnull(bver) && revcomp(a:bver, b:"4")>=0 && revcomp(a:bver, b:"4.3.8_2,1")<=0) {
  txt += 'Package mod_php4 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php5");
if(!isnull(bver) && revcomp(a:bver, b:"5.0.1")<=0) {
  txt += 'Package php5 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php5-cgi");
if(!isnull(bver) && revcomp(a:bver, b:"5.0.1")<=0) {
  txt += 'Package php5-cgi version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php5-cli");
if(!isnull(bver) && revcomp(a:bver, b:"5.0.1")<=0) {
  txt += 'Package php5-cli version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mod_php5");
if(!isnull(bver) && revcomp(a:bver, b:"5.0.1,1")<=0) {
  txt += 'Package mod_php5 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
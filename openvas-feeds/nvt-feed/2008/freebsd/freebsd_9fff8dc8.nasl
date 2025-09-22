# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56067");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-3352");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("FreeBSD Ports: apache");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  apache
   apache+mod_perl
   apache_fp
   apache+ipv6
   ru-apache
   ru-apache+mod_ssl
   apache+ssl
   apache+mod_ssl
   apache+mod_ssl+ipv6
   apache+mod_ssl+mod_accel
   apache+mod_ssl+mod_accel+ipv6
   apache+mod_ssl+mod_accel+mod_deflate
   apache+mod_ssl+mod_accel+mod_deflate+ipv6
   apache+mod_ssl+mod_deflate
   apache+mod_ssl+mod_deflate+ipv6
   apache+mod_ssl+mod_snmp
   apache+mod_ssl+mod_snmp+mod_accel
   apache+mod_ssl+mod_snmp+mod_accel+ipv6
   apache+mod_ssl+mod_snmp+mod_deflate
   apache+mod_ssl+mod_snmp+mod_deflate+ipv6
   apache+mod_ssl+mod_snmp+mod_accel+mod_deflate+ipv6

CVE-2005-3352
Cross-site scripting (XSS) vulnerability in the mod_imap module allows
remote attackers to inject arbitrary web script or HTML via the
Referer when using image maps.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.apacheweek.com/features/security-13");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15834");
  script_xref(name:"URL", value:"http://www.apacheweek.com/features/security-20");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/9fff8dc8-7aa7-11da-bf72-00123f589060.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"1.3")>=0 && revcomp(a:bver, b:"1.3.34_3")<0) {
  txt += 'Package apache version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0.35")>=0 && revcomp(a:bver, b:"2.0.55_2")<0) {
  txt += 'Package apache version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.1")>=0 && revcomp(a:bver, b:"2.1.9_3")<0) {
  txt += 'Package apache version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.2")>=0 && revcomp(a:bver, b:"2.2.0_3")<0) {
  txt += 'Package apache version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_perl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34_1")<0) {
  txt += 'Package apache+mod_perl version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache_fp");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package apache_fp version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package apache+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ru-apache");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+30.22_1")<0) {
  txt += 'Package ru-apache version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ru-apache+mod_ssl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+30.22+2.8.25_1")<0) {
  txt += 'Package ru-apache+mod_ssl version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+ssl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.0")>=0 && revcomp(a:bver, b:"1.3.33.1.55_2")<0) {
  txt += 'Package apache+ssl version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
  txt += 'Package apache+mod_ssl version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
  txt += 'Package apache+mod_ssl+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+mod_accel");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
  txt += 'Package apache+mod_ssl+mod_accel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+mod_accel+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
  txt += 'Package apache+mod_ssl+mod_accel+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+mod_accel+mod_deflate");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
  txt += 'Package apache+mod_ssl+mod_accel+mod_deflate version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+mod_accel+mod_deflate+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
  txt += 'Package apache+mod_ssl+mod_accel+mod_deflate+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+mod_deflate");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
  txt += 'Package apache+mod_ssl+mod_deflate version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+mod_deflate+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
  txt += 'Package apache+mod_ssl+mod_deflate+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
  txt += 'Package apache+mod_ssl+mod_snmp version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp+mod_accel");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
  txt += 'Package apache+mod_ssl+mod_snmp+mod_accel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp+mod_accel+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
  txt += 'Package apache+mod_ssl+mod_snmp+mod_accel+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp+mod_deflate");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
  txt += 'Package apache+mod_ssl+mod_snmp+mod_deflate version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp+mod_deflate+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
  txt += 'Package apache+mod_ssl+mod_snmp+mod_deflate+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp+mod_accel+mod_deflate+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.34+2.8.25_1")<0) {
  txt += 'Package apache+mod_ssl+mod_snmp+mod_accel+mod_deflate+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57145");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-3747");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: apache");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  apache, apache+mod_perl, apache+ipv6, apache_fp, ru-apache, ru-apache+mod_ssl,
  apache+ssl, apache+mod_ssl, apache+mod_ssl+ipv6, apache+mod_ssl+mod_accel,
  apache+mod_ssl+mod_accel+ipv6, apache+mod_ssl+mod_accel+mod_deflate,
  apache+mod_ssl+mod_accel+mod_deflate+ipv6, apache+mod_ssl+mod_deflate,
  apache+mod_ssl+mod_deflate+ipv6, apache+mod_ssl+mod_snmp,
  apache+mod_ssl+mod_snmp+mod_accel, apache+mod_ssl+mod_snmp+mod_accel+ipv6,
  apache+mod_ssl+mod_snmp+mod_deflate, apache+mod_ssl+mod_snmp+mod_deflate+ipv6,
  apache+mod_ssl+mod_snmp+mod_accel+mod_deflate+ipv6");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://marc.info/?l=apache-httpd-announce&m=115409818602955");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/dc8c08c7-1e7c-11db-88cf-000c6ec775d9.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36_1")<0) {
  txt += 'Package apache version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0.46")>=0 && revcomp(a:bver, b:"2.0.58_2")<0) {
  txt += 'Package apache version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.2.0")>=0 && revcomp(a:bver, b:"2.2.2_1")<0) {
  txt += 'Package apache version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_perl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36_1")<0) {
  txt += 'Package apache+mod_perl version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.37")<0) {
  txt += 'Package apache+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache_fp");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package apache_fp version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ru-apache");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package ru-apache version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ru-apache+mod_ssl");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package ru-apache+mod_ssl version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+ssl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.34.1.57_2")<0) {
  txt += 'Package apache+ssl version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
  txt += 'Package apache+mod_ssl version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
  txt += 'Package apache+mod_ssl+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+mod_accel");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
  txt += 'Package apache+mod_ssl+mod_accel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+mod_accel+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
  txt += 'Package apache+mod_ssl+mod_accel+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+mod_accel+mod_deflate");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
  txt += 'Package apache+mod_ssl+mod_accel+mod_deflate version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+mod_accel+mod_deflate+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
  txt += 'Package apache+mod_ssl+mod_accel+mod_deflate+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+mod_deflate");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
  txt += 'Package apache+mod_ssl+mod_deflate version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+mod_deflate+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
  txt += 'Package apache+mod_ssl+mod_deflate+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
  txt += 'Package apache+mod_ssl+mod_snmp version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp+mod_accel");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
  txt += 'Package apache+mod_ssl+mod_snmp+mod_accel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp+mod_accel+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
  txt += 'Package apache+mod_ssl+mod_snmp+mod_accel+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp+mod_deflate");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
  txt += 'Package apache+mod_ssl+mod_snmp+mod_deflate version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp+mod_deflate+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
  txt += 'Package apache+mod_ssl+mod_snmp+mod_deflate+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"apache+mod_ssl+mod_snmp+mod_accel+mod_deflate+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.28")>=0 && revcomp(a:bver, b:"1.3.36+2.8.27_1")<0) {
  txt += 'Package apache+mod_ssl+mod_snmp+mod_accel+mod_deflate+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
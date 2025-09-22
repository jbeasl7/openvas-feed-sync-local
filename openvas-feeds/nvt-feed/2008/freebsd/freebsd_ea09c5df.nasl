# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57375");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-4481", "CVE-2006-4482", "CVE-2006-4483", "CVE-2006-4484", "CVE-2006-4485", "CVE-2006-4486");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: php4, php5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  php4 php5 php4-cli php5-cli php4-cgi php5-cgi php4-dtc php5-dtc
   php4-horde php5-horde php4-nms php5-nms mod_php4 mod_php5");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.php.net/release_4_4_4.php");
  script_xref(name:"URL", value:"http://www.php.net/release_5_1_5.php");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/ea09c5df-4362-11db-81e1-000e0c2e438a.html");

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

bver = portver(pkg:"php4");
if(!isnull(bver) && revcomp(a:bver, b:"4.4.4")<0) {
  txt += 'Package php4 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"5")>=0 && revcomp(a:bver, b:"5.1.5")<0) {
  txt += 'Package php4 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php5");
if(!isnull(bver) && revcomp(a:bver, b:"4.4.4")<0) {
  txt += 'Package php5 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"5")>=0 && revcomp(a:bver, b:"5.1.5")<0) {
  txt += 'Package php5 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php4-cli");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package php4-cli version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php5-cli");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package php5-cli version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php4-cgi");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package php4-cgi version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php5-cgi");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package php5-cgi version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php4-dtc");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package php4-dtc version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php5-dtc");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package php5-dtc version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php4-horde");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package php4-horde version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php5-horde");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package php5-horde version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php4-nms");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package php4-nms version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php5-nms");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package php5-nms version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mod_php4");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package mod_php4 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mod_php5");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package mod_php5 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
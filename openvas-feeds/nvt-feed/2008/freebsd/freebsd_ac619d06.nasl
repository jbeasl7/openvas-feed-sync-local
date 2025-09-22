# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52292");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-1029");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: jdk");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-57591-1&searchclause=%22category:security%22%20%22availability,%20security%22");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11726");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/382072");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=110125046627909");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/ac619d06-3ef8-11d9-8741-c942c075aa41.html");

  script_tag(name:"insight", value:"The following packages are affected:

  jdk, linux-jdk, linux-sun-jdk, linux-blackdown-jdk, linux-ibm-jdk,
  diablo-jdk, diablo-jre

CVE-2004-1029
The Sun Java Plugin capability in Java 2 Runtime Environment (JRE)
1.4.2_01, 1.4.2_04, and possibly earlier versions, does not properly
restrict access between Javascript and Java applets during data
transfer, which allows remote attackers to load unsafe classes and
execute arbitrary code.");

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

bver = portver(pkg:"jdk");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.0")>=0 && revcomp(a:bver, b:"1.4.2p6_6")<=0) {
  txt += 'Package jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.3.0")>=0 && revcomp(a:bver, b:"1.3.1p9_4")<=0) {
  txt += 'Package jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-jdk");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.0")>=0 && revcomp(a:bver, b:"1.4.2.05")<=0) {
  txt += 'Package linux-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.3.0")>=0 && revcomp(a:bver, b:"1.3.1.13")<=0) {
  txt += 'Package linux-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-sun-jdk");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.0")>=0 && revcomp(a:bver, b:"1.4.2.05")<=0) {
  txt += 'Package linux-sun-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.3.0")>=0 && revcomp(a:bver, b:"1.3.1.13")<=0) {
  txt += 'Package linux-sun-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-blackdown-jdk");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.0")>=0 && revcomp(a:bver, b:"1.4.2")<=0) {
  txt += 'Package linux-blackdown-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-ibm-jdk");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.0")>=0 && revcomp(a:bver, b:"1.4.2")<=0) {
  txt += 'Package linux-ibm-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"diablo-jdk");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.1.0")>=0 && revcomp(a:bver, b:"1.3.1.0_1")<=0) {
  txt += 'Package diablo-jdk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"diablo-jre");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.1.0")>=0 && revcomp(a:bver, b:"1.3.1.0_1")<=0) {
  txt += 'Package diablo-jre version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
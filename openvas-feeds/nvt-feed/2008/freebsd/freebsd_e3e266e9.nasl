# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52263");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-1125");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: xpdf");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  xpdf
   kdegraphics
   gpdf
   teTeX-base
   cups-base
   koffice
   pdftohtml

CVE-2004-1125
Buffer overflow in the Gfx::doImage function in Gfx.cc for xpdf 3.00,
and other products that share code such as tetex-bin and kpdf in KDE
3.2.x to 3.2.3 and 3.3.x to 3.3.2, allows remote attackers to cause a
denial of service (application crash) and possibly execute arbitrary
code via a crafted PDF file that causes the boundaries of a maskColors
array to be exceeded.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.idefense.com/application/poi/display?id=172&type=vulnerabilities");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/e3e266e9-5473-11d9-a9e7-0001020eed82.html");

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

bver = portver(pkg:"xpdf");
if(!isnull(bver) && revcomp(a:bver, b:"3.00_5")<0) {
  txt += 'Package xpdf version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"kdegraphics");
if(!isnull(bver) && revcomp(a:bver, b:"3.3.2_1")<0) {
  txt += 'Package kdegraphics version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"gpdf");
if(!isnull(bver) && revcomp(a:bver, b:"2.8.1")<=0) {
  txt += 'Package gpdf version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"teTeX-base");
if(!isnull(bver) && revcomp(a:bver, b:"2.0.2_6")<=0) {
  txt += 'Package teTeX-base version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"cups-base");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.22.0")<=0) {
  txt += 'Package cups-base version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"koffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.5,1")<=0) {
  txt += 'Package koffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"pdftohtml");
if(!isnull(bver) && revcomp(a:bver, b:"0.36_1")<0) {
  txt += 'Package pdftohtml version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
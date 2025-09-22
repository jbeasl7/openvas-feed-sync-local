# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58817");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2007-3387");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: xpdf, zh-xpdf, ja-xpdf, ko-xpdf");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  xpdf
   zh-xpdf
   ja-xpdf
   ko-xpdf
   kdegraphics
   cups-base
   gpdf
   pdftohtml
   poppler");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.kde.org/info/security/advisory-20070730-1.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/25124");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/0e43a14d-3f3f-11dc-a79a-0016179b2dd5.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"3.02_2")<0) {
  txt += 'Package xpdf version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"zh-xpdf");
if(!isnull(bver) && revcomp(a:bver, b:"3.02_2")<0) {
  txt += 'Package zh-xpdf version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ja-xpdf");
if(!isnull(bver) && revcomp(a:bver, b:"3.02_2")<0) {
  txt += 'Package ja-xpdf version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ko-xpdf");
if(!isnull(bver) && revcomp(a:bver, b:"3.02_2")<0) {
  txt += 'Package ko-xpdf version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"kdegraphics");
if(!isnull(bver) && revcomp(a:bver, b:"3.5.7_1")<0) {
  txt += 'Package kdegraphics version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"cups-base");
if(!isnull(bver) && revcomp(a:bver, b:"1.2.11_3")<0) {
  txt += 'Package cups-base version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"gpdf");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package gpdf version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"pdftohtml");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package pdftohtml version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"poppler");
if(!isnull(bver) && revcomp(a:bver, b:"0.5.9_4")<0) {
  txt += 'Package poppler version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
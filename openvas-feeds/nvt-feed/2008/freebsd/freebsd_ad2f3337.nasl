# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52322");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0888", "CVE-2004-0889");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: gpdf, cups-base");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  gpdf
   cups-base
   xpdf
   kdegraphics
   koffice
   teTeX-base

CVE-2004-0888
Multiple integer overflows in xpdf 2.0 and 3.0, and other packages
that use xpdf code such as CUPS, gpdf, and kdegraphics, allow remote
attackers to cause a denial of service (crash) and possibly execute
arbitrary code, a different set of vulnerabilities than those
identified by CVE-2004-0889.

CVE-2004-0889
Multiple integer overflows in xpdf 3.0, and other packages that use
xpdf code such as CUPS, allow remote attackers to cause a denial of
service (crash) and possibly execute arbitrary code, a different set
of vulnerabilities than those identified by CVE-2004-0888.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://scary.beasts.org/security/CESA-2004-002.txt");
  script_xref(name:"URL", value:"http://scary.beasts.org/security/CESA-2004-007.txt");
  script_xref(name:"URL", value:"http://www.kde.org/info/security/advisory-20041021-1.txt");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/ad2f3337-26bf-11d9-9289-000c41e2cdad.html");

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

bver = portver(pkg:"gpdf");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.22.0")<0) {
  txt += 'Package gpdf version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"cups-base");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.22.0")<0) {
  txt += 'Package cups-base version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"xpdf");
if(!isnull(bver) && revcomp(a:bver, b:"3.00_4")<0) {
  txt += 'Package xpdf version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"kdegraphics");
if(!isnull(bver) && revcomp(a:bver, b:"3.3.0_1")<0) {
  txt += 'Package kdegraphics version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"koffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.2_1,1")<0) {
  txt += 'Package koffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"teTeX-base");
if(!isnull(bver) && revcomp(a:bver, b:"2.0.2_4")<0) {
  txt += 'Package teTeX-base version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
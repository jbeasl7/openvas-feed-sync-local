# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52386");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0687", "CVE-2004-0688");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("xpm -- image decoding vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  agenda-snow-libs
   linux_base
   open-motif-devel
   mupad
   zh-cle_base
   libXpm
   XFree86-libraries
   xorg-libraries
   lesstif
   xpm
   linux-openmotif
   open-motif

CVE-2004-0687
Multiple stack-based buffer overflows in (1) xpmParseColors in
parse.c, (2) ParseAndPutPixels in create.c, and (3) ParsePixels in
parse.c for libXpm before 6.8.1 allow remote attackers to execute
arbitrary code via a malformed XPM image file.

CVE-2004-0688
Multiple integer overflows in (1) the xpmParseColors function in
parse.c, (2) XpmCreateImageFromXpmImage, (3) CreateXImage, (4)
ParsePixels, and (5) ParseAndPutPixels for libXpm before 6.8.1 may
allow remote attackers to execute arbitrary code via a malformed XPM
image file.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://freedesktop.org/pipermail/xorg/2004-September/003172.html");
  script_xref(name:"URL", value:"http://scary.beasts.org/security/CESA-2004-003.txt");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/ef253f8b-0727-11d9-b45d-000c41e2cdad.html");

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

bver = portver(pkg:"agenda-snow-libs");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package agenda-snow-libs version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux_base");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package linux_base version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"open-motif-devel");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package open-motif-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mupad");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package mupad version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"zh-cle_base");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package zh-cle_base version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"libXpm");
if(!isnull(bver) && revcomp(a:bver, b:"3.5.1_1")<0) {
  txt += 'Package libXpm version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"XFree86-libraries");
if(!isnull(bver) && revcomp(a:bver, b:"4.4.0_1")<0) {
  txt += 'Package XFree86-libraries version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"xorg-libraries");
if(!isnull(bver) && revcomp(a:bver, b:"6.7.0_2")<0) {
  txt += 'Package xorg-libraries version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"lesstif");
if(!isnull(bver) && revcomp(a:bver, b:"0.93.96,2")<0) {
  txt += 'Package lesstif version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"xpm");
if(!isnull(bver) && revcomp(a:bver, b:"3.4k_1")<0) {
  txt += 'Package xpm version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-openmotif");
if(!isnull(bver) && revcomp(a:bver, b:"2.2.4")<0) {
  txt += 'Package linux-openmotif version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"open-motif");
if(!isnull(bver) && revcomp(a:bver, b:"2.2.3_1")<0) {
  txt += 'Package open-motif version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
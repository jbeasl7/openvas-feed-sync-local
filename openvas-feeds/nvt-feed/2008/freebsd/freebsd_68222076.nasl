# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54465");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-1544");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: tiff");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  tiff
   linux-tiff
   pdflib
   pdflib-perl
   fractorama
   gdal
   iv
   ivtools
   ja-iv
   ja-libimg
   paraview

CVE-2005-1544
Stack-based buffer overflow in libTIFF before 1.53 allows remote
attackers to execute arbitrary code via a TIFF file with a malformed
BitsPerSample tag.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://bugzilla.remotesensing.org/show_bug.cgi?id=843");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13585");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200505-07.xml");
  script_xref(name:"URL", value:"http://www.remotesensing.org/libtiff/v3.7.3.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/68222076-010b-11da-bc08-0001020eed82.html");

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

bver = portver(pkg:"tiff");
if(!isnull(bver) && revcomp(a:bver, b:"3.7.3")<0) {
  txt += 'Package tiff version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-tiff");
if(!isnull(bver) && revcomp(a:bver, b:"3.6.1_3")<0) {
  txt += 'Package linux-tiff version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"pdflib");
if(!isnull(bver) && revcomp(a:bver, b:"6.0.1_2")<0) {
  txt += 'Package pdflib version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"pdflib-perl");
if(!isnull(bver) && revcomp(a:bver, b:"6.0.1_2")<0) {
  txt += 'Package pdflib-perl version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"fractorama");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package fractorama version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"gdal");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package gdal version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"iv");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package iv version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ivtools");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package ivtools version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ja-iv");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package ja-iv version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ja-libimg");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package ja-libimg version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"paraview");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package paraview version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
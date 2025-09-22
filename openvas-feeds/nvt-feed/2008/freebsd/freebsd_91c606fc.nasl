# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52545");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-1195");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("mplayer & libxine -- MMS and Real RTSP buffer overflow vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  mplayer
   mplayer-gtk
   mplayer-gtk2
   mplayer-esound
   mplayer-gtk-esound
   mplayer-gtk2-esound
   libxine

CVE-2005-1195
Multiple heap-based buffer overflows in the code used to handle (1)
MMST streams or (2) RealMedia RTSP streams in MPlayer 1.0pre6 and
earlier allow remote malicious servers to execute arbitrary code.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.mplayerhq.hu/homepage/design7/news.html#vuln10");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13270");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13271");
  script_xref(name:"URL", value:"http://www.mplayerhq.hu/homepage/design7/news.html#vuln11");
  script_xref(name:"URL", value:"http://xinehq.de/index.php/security/XSA-2004-8");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/91c606fc-b5d0-11d9-a788-0001020eed82.html");

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

bver = portver(pkg:"mplayer");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.7")<0) {
  txt += 'Package mplayer version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mplayer-gtk");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.7")<0) {
  txt += 'Package mplayer-gtk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mplayer-gtk2");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.7")<0) {
  txt += 'Package mplayer-gtk2 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mplayer-esound");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.7")<0) {
  txt += 'Package mplayer-esound version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mplayer-gtk-esound");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.7")<0) {
  txt += 'Package mplayer-gtk-esound version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mplayer-gtk2-esound");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.7")<0) {
  txt += 'Package mplayer-gtk2-esound version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"libxine");
if(!isnull(bver) && revcomp(a:bver, b:"0.9.9")>=0 && revcomp(a:bver, b:"1.0.1")<0) {
  txt += 'Package libxine version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
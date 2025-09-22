# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52266");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-1187", "CVE-2004-1188");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("mplayer -- multiple vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  mplayer, mplayer-gtk, mplayer-gtk2, mplayer-esound, mplayer-gtk-esound
  mplayer-gtk2-esound, libxine

CVE-2004-1187
Heap-based buffer overflow in the pnm_get_chunk function for xine
0.99.2, and other packages such as MPlayer that use the same code,
allows remote attackers to execute arbitrary code via long PNA_TAG
values, a different vulnerability than CVE-2004-1188.

CVE-2004-1188
The pnm_get_chunk function in xine 0.99.2 and earlier, and other
packages such as MPlayer that use the same code, does not properly
verify that the chunk size is less than the PREAMBLE_SIZE, which
causes a read operation with a negative length that leads to a buffer
overflow via (1) RMF_TAG, (2) DATA_TAG, (3) PROP_TAG, (4) MDPR_TAG,
and (5) CONT_TAG values, a different vulnerability than CVE-2004-1187.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://mplayerhq.hu/homepage/design7/news.html#mplayer10pre5try2");
  script_xref(name:"URL", value:"http://www.idefense.com/application/poi/display?id=166");
  script_xref(name:"URL", value:"http://www.idefense.com/application/poi/display?id=167");
  script_xref(name:"URL", value:"http://www.idefense.com/application/poi/display?id=168");
  script_xref(name:"URL", value:"http://xinehq.de/index.php/security/XSA-2004-6");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=110322526210300");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=110322829807443");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=110323022605345");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/85d76f02-5380-11d9-a9e7-0001020eed82.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"0.99.5_5")<0) {
  txt += 'Package mplayer version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mplayer-gtk");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.5_5")<0) {
  txt += 'Package mplayer-gtk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mplayer-gtk2");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.5_5")<0) {
  txt += 'Package mplayer-gtk2 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mplayer-esound");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.5_5")<0) {
  txt += 'Package mplayer-esound version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mplayer-gtk-esound");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.5_5")<0) {
  txt += 'Package mplayer-gtk-esound version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mplayer-gtk2-esound");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.5_5")<0) {
  txt += 'Package mplayer-gtk2-esound version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"libxine");
if(!isnull(bver) && revcomp(a:bver, b:"1.0.r5_3")<=0) {
  txt += 'Package libxine version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
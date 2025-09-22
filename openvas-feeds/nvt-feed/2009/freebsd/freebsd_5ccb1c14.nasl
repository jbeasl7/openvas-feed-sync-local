# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63240");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-01-20 22:42:09 +0100 (Tue, 20 Jan 2009)");
  script_cve_id("CVE-2008-3162");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("mplayer -- vulnerability in STR files processor");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  mplayer
   mplayer-esound
   mplayer-gtk
   mplayer-gtk-esound
   mplayer-gtk2
   mplayer-gtk2-esound

CVE-2008-3162
Stack-based buffer overflow in the str_read_packet function in
libavformat/psxstr.c in FFmpeg before r13993 allows remote attackers
to cause a denial of service (application crash) or execute arbitrary
code via a crafted STR file that interleaves audio and video sectors.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/30994");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30157");
  script_xref(name:"URL", value:"https://roundup.mplayerhq.hu/roundup/ffmpeg/issue311");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/5ccb1c14-e357-11dd-a765-0030843d3802.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"0.99.11_10")<0) {
  txt += 'Package mplayer version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mplayer-esound");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.11_10")<0) {
  txt += 'Package mplayer-esound version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mplayer-gtk");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.11_10")<0) {
  txt += 'Package mplayer-gtk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mplayer-gtk-esound");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.11_10")<0) {
  txt += 'Package mplayer-gtk-esound version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mplayer-gtk2");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.11_10")<0) {
  txt += 'Package mplayer-gtk2 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mplayer-gtk2-esound");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.11_10")<0) {
  txt += 'Package mplayer-gtk2-esound version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
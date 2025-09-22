# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63999");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-20 00:17:15 +0200 (Wed, 20 May 2009)");
  script_cve_id("CVE-2009-0385", "CVE-2009-1274");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: libxine");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: libxine

CVE-2009-0385
Integer signedness error in the fourxm_read_header function in
libavformat/4xm.c in FFmpeg before revision 16846 allows remote
attackers to execute arbitrary code via a malformed 4X movie file with
a large current_track value, which triggers a NULL pointer
dereference.

CVE-2009-1274
Integer overflow in the qt_error parse_trak_atom function in
demuxers/demux_qt.c in xine-lib 1.1.16.2 and earlier allows remote
attackers to execute arbitrary code via a Quicktime movie file with a
large count value in an STTS atom, which triggers a heap-based buffer
overflow.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://trapkit.de/advisories/TKADV2009-004.txt");
  script_xref(name:"URL", value:"http://trapkit.de/advisories/TKADV2009-005.txt");
  script_xref(name:"URL", value:"http://sourceforge.net/project/shownotes.php?release_id=660071");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/48e14d86-42f1-11de-ad22-000e35248ad7.html");

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

bver = portver(pkg:"libxine");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.16.3")<0) {
  txt += 'Package libxine version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
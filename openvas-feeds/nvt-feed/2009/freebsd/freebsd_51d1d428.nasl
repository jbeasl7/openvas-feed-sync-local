# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64000");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-20 00:17:15 +0200 (Wed, 20 May 2009)");
  script_cve_id("CVE-2009-0698", "CVE-2008-5234", "CVE-2008-5240");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: libxine");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: libxine

CVE-2009-0698
Integer overflow in the 4xm demuxer (demuxers/demux_4xm.c) in xine-lib
1.1.16.1 allows remote attackers to cause a denial of service (crash)
and possibly execute arbitrary code via a 4X movie file with a large
current_track value, a similar issue to CVE-2009-0385.

CVE-2008-5234
Multiple heap-based buffer overflows in xine-lib 1.1.12, and other
versions before 1.1.15, allow remote attackers to execute arbitrary
code via vectors related to (1) a crafted metadata atom size processed
by the parse_moov_atom function in demux_qt.c and (2) frame reading in
the id3v23_interp_frame function in id3.c.  NOTE: as of 20081122, it is
possible that vector 1 has not been fixed in 1.1.15.

CVE-2008-5240
xine-lib 1.1.12, and other 1.1.15 and earlier versions, relies on an
untrusted input value to determine the memory allocation and does not
check the result for (1) the MATROSKA_ID_TR_CODECPRIVATE track entry
element processed by demux_matroska.c, and (2) PROP_TAG, (3) MDPR_TAG,
and (4) CONT_TAG chunks processed by the real_parse_headers function
in demux_real.c, which allows remote attackers to cause a denial of
service (NULL pointer dereference and crash) or possibly execute
arbitrary code via a crafted value.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://trapkit.de/advisories/TKADV2009-004.txt");
  script_xref(name:"URL", value:"http://sourceforge.net/project/shownotes.php?release_id=660071");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/51d1d428-42f0-11de-ad22-000e35248ad7.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"1.1.16.2")<0) {
  txt += 'Package libxine version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
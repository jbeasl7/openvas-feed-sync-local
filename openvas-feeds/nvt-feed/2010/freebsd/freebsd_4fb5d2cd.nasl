# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67361");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-05-04 05:52:15 +0200 (Tue, 04 May 2010)");
  script_cve_id("CVE-2010-0205");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("FreeBSD Ports: png");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: png

CVE-2010-0205
The png_decompress_chunk function in pngrutil.c in libpng 1.0.x before
1.0.53, 1.2.x before 1.2.43, and 1.4.x before 1.4.1 does not properly
handle compressed ancillary-chunk data that has a disproportionately
large uncompressed representation, which allows remote attackers to
cause a denial of service (memory and CPU consumption, and application
hang) via a crafted PNG file, as demonstrated by use of the deflate
compression method on data composed of many occurrences of the same
character, related to a 'decompression bomb' attack.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://libpng.sourceforge.net/ADVISORY-1.4.1.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38478");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38774");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56661");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/4fb5d2cd-4c77-11df-83fb-0015587e2cc1.html");

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

bver = portver(pkg:"png");
if(!isnull(bver) && revcomp(a:bver, b:"1.2.43")>0 && revcomp(a:bver, b:"1.4.1")<0) {
  txt += 'Package png version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
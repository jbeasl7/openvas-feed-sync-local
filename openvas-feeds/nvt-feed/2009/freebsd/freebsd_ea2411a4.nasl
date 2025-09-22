# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63514");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-07 21:47:03 +0100 (Sat, 07 Mar 2009)");
  script_cve_id("CVE-2009-0040");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: pngcrush");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: pngcrush

CVE-2009-0040
The PNG reference library (aka libpng) before 1.0.43, and 1.2.x before
1.2.35, as used in pngcrush and other applications, allows
context-dependent attackers to cause a denial of service (application
crash) or possibly execute arbitrary code via a crafted PNG file that
triggers a free of an uninitialized pointer in (1) the png_read_png
function, (2) pCAL chunk handling, or (3) setup of 16-bit gamma
tables.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/33976");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33827");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/48819");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/ea2411a4-08e8-11de-b88a-0022157515b2.html");

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

bver = portver(pkg:"pngcrush");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.14")<0) {
  txt += 'Package pngcrush version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
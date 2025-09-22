# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60115");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2007-5081", "CVE-2007-3410", "CVE-2007-2263", "CVE-2007-2264");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: linux-realplayer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: linux-realplayer

CVE-2007-5081
Heap-based buffer overflow in RealNetworks RealPlayer 8, 10, 10.1, and
possibly 10.5, RealOne Player 1 and 2, and RealPlayer Enterprise
allows remote attackers to execute arbitrary code via a crafted RM
file.

CVE-2007-3410
Stack-based buffer overflow in the SmilTimeValue::parseWallClockValue
function in smlprstime.cpp in RealNetworks RealPlayer 10, 10.1, and
possibly 10.5, RealOne Player, RealPlayer Enterprise, and Helix Player
10.5-GOLD and 10.0.5 through 10.0.8, allows remote attackers to
execute arbitrary code via an SMIL (SMIL2) file with a long wallclock
value.

CVE-2007-2263
Heap-based buffer overflow in RealNetworks RealPlayer 10.0, 10.1, and
possibly 10.5, RealOne Player, and RealPlayer Enterprise allows remote
attackers to execute arbitrary code via an SWF (Flash) file with
malformed record headers.

CVE-2007-2264
Heap-based buffer overflow in RealNetworks RealPlayer 8, 10, 10.1, and
possibly 10.5, RealOne Player 1 and 2, and RealPlayer Enterprise
allows remote attackers to execute arbitrary code via a RAM (.ra or
.ram) file with a large size value in the RA header.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/27361");
  script_xref(name:"URL", value:"http://service.real.com/realplayer/security/10252007_player/en/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-063.html");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-062.html");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-061.html");
  script_xref(name:"URL", value:"http://secunia.com/advisories/25819/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/f762ccbb-baed-11dc-a302-000102cc8983.html");

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

bver = portver(pkg:"linux-realplayer");
if(!isnull(bver) && revcomp(a:bver, b:"10.0.5")>=0 && revcomp(a:bver, b:"10.0.9.809.20070726")<0) {
  txt += 'Package linux-realplayer version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56447");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-2922");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: linux-realplayer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: linux-realplayer

CVE-2005-2922
Heap-based buffer overflow in the embedded player in multiple
RealNetworks products and versions including RealPlayer 10.x, RealOne
Player, and Helix Player allows remote malicious servers to cause a
denial of service (crash) and possibly execute arbitrary code via a
chunked Transfer-Encoding HTTP response in which either (1) the chunk
header length is specified as -1, (2) the chunk header with a length
that is less than the actual amount of sent data, or (3) a missing
chunk header.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://service.real.com/realplayer/security/03162006_player/en/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/17202");
  script_xref(name:"URL", value:"http://www.idefense.com/intelligence/vulnerabilities/display.php?id=404");
  script_xref(name:"URL", value:"http://secunia.com/advisories/19358/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/fe4c84fc-bdb5-11da-b7d4-00123ffe8333.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"10.0.1")>=0 && revcomp(a:bver, b:"10.0.6")<0) {
  txt += 'Package linux-realplayer version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
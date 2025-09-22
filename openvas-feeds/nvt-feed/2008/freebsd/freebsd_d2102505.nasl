# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52384");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0414", "CVE-2004-0416", "CVE-2004-0417", "CVE-2004-0418", "CVE-2004-0778");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: cvs+ipv6");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: cvs+ipv6

CVE-2004-0414
CVS 1.12.x through 1.12.8, and 1.11.x through 1.11.16, does not
properly handle malformed 'Entry' lines, which prevents a NULL
terminator from being used and may lead to a denial of service
(crash), modification of critical program data, or arbitrary code
execution.

CVE-2004-0416
Double-free vulnerability for the error_prog_name string in CVS 1.12.x
through 1.12.8, and 1.11.x through 1.11.16, may allow remote attackers
to execute arbitrary code.

CVE-2004-0417
Integer overflow in the 'Max-dotdot' CVS protocol command
(serve_max_dotdot) for CVS 1.12.x through 1.12.8, and 1.11.x through
1.11.16, may allow remote attackers to cause a server crash, which
could cause temporary data to remain undeleted and consume disk space.

CVE-2004-0418
serve_notify in CVS 1.12.x through 1.12.8, and 1.11.x through 1.11.16,
does not properly handle empty data lines, which may allow remote
attackers to perform an 'out-of-bounds' write for a single byte to
execute arbitrary code or modify critical program data.

CVE-2004-0778
CVS 1.11.x before 1.11.17, and 1.12.x before 1.12.9, allows remote
attackers to determine the existence of arbitrary files and
directories via the -X command for an alternate history file, which
causes different error messages to be returned.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
software upgrades.");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/11817");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10499");
  script_xref(name:"URL", value:"http://secunia.com/advisories/12309");
  script_xref(name:"URL", value:"http://security.e-matters.de/advisories/092004.html");
  script_xref(name:"URL", value:"http://www.idefense.com/application/poi/display?id=130&type=vulnerabilities&flashstatus=false");
  script_xref(name:"URL", value:"https://ccvs.cvshome.org/source/browse/ccvs/NEWS?rev=1.116.2.104");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/d2102505-f03d-11d8-81b0-000347a4fa7d.html");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

txt = "";
vuln = FALSE;

bver = portver(pkg:"cvs+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"1.11.17")<0) {
  txt += 'Package cvs+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
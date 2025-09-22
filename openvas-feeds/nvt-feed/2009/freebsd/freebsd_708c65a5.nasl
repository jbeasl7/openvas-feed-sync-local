# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64581");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
  script_cve_id("CVE-2009-0217");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("FreeBSD Ports: mono");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: mono

CVE-2009-0217
The design of the W3C XML Signature Syntax and Processing (XMLDsig)
recommendation, as implemented in products including (1) the Oracle
Security Developer Tools component in Oracle Application Server
10.1.2.3, 10.1.3.4, and 10.1.4.3IM, (2) the WebLogic Server component
in BEA Product Suite 10.3, 10.0 MP1, 9.2 MP3, 9.1, 9.0, and 8.1 SP6,
(3) Mono before 2.4.2.2, (4) XML Security Library before 1.2.12, (5)
IBM WebSphere Application Server Versions 6.0 through 6.0.2.33, 6.1
through 6.1.0.23, and 7.0 through 7.0.0.1, and other products uses a
parameter that defines an HMAC truncation length (HMACOutputLength)
but does not require a minimum for this length, which allows attackers
to spoof HMAC-based signatures and bypass authentication by specifying
a truncation length with a small number of bits.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35852/");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/466161");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/708c65a5-7c58-11de-a994-0030843d3802.html");

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

bver = portver(pkg:"mono");
if(!isnull(bver) && revcomp(a:bver, b:"2.4.2.2")<0) {
  txt += 'Package mono version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
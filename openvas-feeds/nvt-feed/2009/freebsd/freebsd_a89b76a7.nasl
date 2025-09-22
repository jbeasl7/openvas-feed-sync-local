# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63357");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
  script_cve_id("CVE-2008-5282", "CVE-2009-0323");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: amaya");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: amaya

CVE-2008-5282
Multiple stack-based buffer overflows in W3C Amaya Web Browser 10.0.1
allow remote attackers to execute arbitrary code via (1) a link with a
long HREF attribute, and (2) a DIV tag with a long id attribute.

CVE-2009-0323
Multiple stack-based buffer overflows in W3C Amaya Web Browser 10.0
and 11.0 allow remote attackers to execute arbitrary code via (1) a
long type parameter in an input tag, which is not properly handled by
the EndOfXmlAttributeValue function, (2) an 'HTML GI' in a start tag,
which is not properly handled by the ProcessStartGI function, and
unspecified vectors in (3) html2thot.c and (4) xml2thot.c, related to
the msgBuffer variable.  NOTE: these are different vectors than
CVE-2008-6005.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32848/");
  script_xref(name:"URL", value:"http://www.bmgsec.com.au/advisory/41/");
  script_xref(name:"URL", value:"http://www.bmgsec.com.au/advisory/40/");
  script_xref(name:"URL", value:"http://milw0rm.com/exploits/7467");
  script_xref(name:"URL", value:"http://www.coresecurity.com/content/amaya-buffer-overflows");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/a89b76a7-f6bd-11dd-94d9-0030843d3802.html");

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

bver = portver(pkg:"amaya");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package amaya version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
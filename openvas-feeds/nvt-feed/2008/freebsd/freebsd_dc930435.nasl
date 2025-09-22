# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56650");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-1900");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: amaya");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: amaya

CVE-2006-1900
Multiple buffer overflows in World Wide Web Consortium (W3C) Amaya
9.4, and possibly other versions including 8.x before 8.8.5, allow
remote attackers to execute arbitrary code via a long value in (1) the
COMPACT attribute of the COLGROUP element, (2) the ROWS attribute of
the TEXTAREA element, and (3) the COLOR attribute of the LEGEND
element, and via other unspecified attack vectors consisting of
'dozens of possible snippets.'");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://morph3us.org/advisories/20060412-amaya-94.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/17507");
  script_xref(name:"URL", value:"http://morph3us.org/advisories/20060412-amaya-94-2.txt");
  script_xref(name:"URL", value:"http://secunia.com/advisories/19670/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/dc930435-d59f-11da-8098-00123ffe8333.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"9.5")<0) {
  txt += 'Package amaya version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
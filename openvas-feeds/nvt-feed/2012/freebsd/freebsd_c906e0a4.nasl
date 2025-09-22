# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71833");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2012-3508");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-08-30 11:34:17 -0400 (Thu, 30 Aug 2012)");
  script_name("FreeBSD Ports: roundcube");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: roundcube

CVE-2012-3508
Cross-site scripting (XSS) vulnerability in program/lib/washtml.php in
Roundcube Webmail 0.8.0 allows remote attackers to inject arbitrary
web script or HTML by using 'javascript:' in an href attribute in the
body of an HTML-formatted email.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://trac.roundcube.net/wiki/Changelog");
  script_xref(name:"URL", value:"http://trac.roundcube.net/ticket/1488613");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/c906e0a4-efa6-11e1-8fbf-001b77d09812.html");

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

bver = portver(pkg:"roundcube");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.0,1")>=0 && revcomp(a:bver, b:"0.8.1,1")<0) {
  txt += "Package roundcube version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
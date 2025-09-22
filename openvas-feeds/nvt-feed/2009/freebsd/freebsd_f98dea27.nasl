# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63093");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-01-02 18:22:54 +0100 (Fri, 02 Jan 2009)");
  script_cve_id("CVE-2008-5304", "CVE-2008-5305");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: twiki");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: twiki

CVE-2008-5304
Cross-site scripting (XSS) vulnerability in TWiki before 4.2.4 allows
remote attackers to inject arbitrary web script or HTML via the
%URLPARAM{}% variable.
CVE-2008-5305
Eval injection vulnerability in TWiki before 4.2.4 allows remote
attackers to execute arbitrary Perl code via the %SEARCH{}% variable.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/33040");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32668");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32669");
  script_xref(name:"URL", value:"http://twiki.org/cgi-bin/view/Codev/SecurityAlert-CVE-2008-5304");
  script_xref(name:"URL", value:"http://twiki.org/cgi-bin/view/Codev/SecurityAlert-CVE-2008-5305");
  script_xref(name:"URL", value:"http://www.securitytracker.com/alerts/2008/Dec/1021351.html");
  script_xref(name:"URL", value:"http://www.securitytracker.com/alerts/2008/Dec/1021352.html");
  script_xref(name:"URL", value:"https://www.it-isac.org/postings/cyber/alertdetail.php?id=4513");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/45293");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/f98dea27-d687-11dd-abd1-0050568452ac.html");

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

bver = portver(pkg:"twiki");
if(!isnull(bver) && revcomp(a:bver, b:"4.2.4,1")<0) {
  txt += 'Package twiki version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
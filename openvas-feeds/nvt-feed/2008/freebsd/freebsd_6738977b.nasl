# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56772");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-1909");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("FreeBSD Ports: coppermine");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: coppermine

CVE-2006-1909
Directory traversal vulnerability in index.php in Coppermine 1.4.4
allows remote attackers to read arbitrary files via a .//./ (modified
dot dot slash) in the file parameter, which causes a regular
expression to collapse the sequences into standard '../' sequences.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://coppermine-gallery.net/forum/index.php?topic=30655.0");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/17570");
  script_xref(name:"URL", value:"http://myimei.com/security/2006-04-14/copperminephotogallery144-plugininclusionsystemindexphp-remotefileinclusion-attack.html");
  script_xref(name:"URL", value:"http://secunia.com/advisories/19665/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/6738977b-e9a5-11da-b9f4-00123ffe8333.html");

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

bver = portver(pkg:"coppermine");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.5")<0) {
  txt += 'Package coppermine version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
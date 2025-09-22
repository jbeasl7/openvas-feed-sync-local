# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54492");
  script_version("2023-07-26T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:08 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-1621", "CVE-2005-1695", "CVE-2005-1696", "CVE-2005-1698", "CVE-2005-1777", "CVE-2005-1778", "CVE-2005-1921");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: postnuke");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: postnuke

CVE-2005-1621
Directory traversal vulnerability in the pnModFunc function in
pnMod.php for PostNuke 0.750 through 0.760rc4 allows remote attackers
to read arbitrary files via a .. (dot dot) in the func parameter to
index.php.

CVE-2005-1695
Multiple cross-site scripting (XSS) vulnerabilities in the RSS module
in PostNuke 0.750 and 0.760RC2 and RC3 allow remote attackers to
inject arbitrary web script or HTML via the (1) rss_url parameter to
magpie_slashbox.php, or the url parameter to (2) magpie_simple.php or
(3) magpie_debug.php.

CVE-2005-1696
Multiple cross-site scripting (XSS) vulnerabilities in PostNuke 0.750
and 0.760RC3 allow remote attackers to inject arbitrary web script or
HTML via the (1) skin or (2) paletteid parameter to demo.php in the
Xanthia module, or (3) the serverName parameter to config.php in the
Multisites (aka NS-Multisites) module.

CVE-2005-1698
PostNuke 0.750 and 0.760RC3 allows remote attackers to obtain
sensitive information via a direct request to (1) theme.php or (2)
Xanthia.php in the Xanthia module, (3) user.php, (4) thelang.php, (5)
text.php, (6) html.php, (7) menu.php, (8) finclude.php, or (9)
button.php in the pnblocks directory in the Blocks module, (10)
config.php in the NS-Multisites (aka Multisites) module, or (11)
xmlrpc.php, which reveals the path in an error message.

CVE-2005-1777
SQL injection vulnerability in readpmsg.php in PostNuke 0.750 allows
remote attackers to execute arbitrary SQL commands via the start
parameter.

CVE-2005-1778
Cross-site scripting (XSS) vulnerability in readpmsg.php in PostNuke
0.750 allows remote attackers to inject arbitrary web script or HTML
via the start parameter.

CVE-2005-1921
PEAR XML_RPC 1.3.0 and earlier (aka XML-RPC or xmlrpc) and PHPXMLRPC
(aka XML-RPC For PHP or php-xmlrpc) 1.1 and earlier, as used in
products such as (1) WordPress, (2) Serendipity, (3) Drupal, (4)
egroupware, (5) MailWatch, (6) TikiWiki, (7) phpWebSite, (8) Ampache,
and others, allows remote attackers to execute arbitrary PHP code via
an XML file, which is not properly sanitized before being used in an
eval statement.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/15450/");
  script_xref(name:"URL", value:"http://news.postnuke.com/Article2691.html");
  script_xref(name:"URL", value:"http://news.postnuke.com/Article2699.html");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=111721364707520");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/0274a9f1-0759-11da-bc08-0001020eed82.html");

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

bver = portver(pkg:"postnuke");
if(!isnull(bver) && revcomp(a:bver, b:"0.760")<0) {
  txt += 'Package postnuke version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
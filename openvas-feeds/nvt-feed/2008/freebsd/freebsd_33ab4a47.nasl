# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52438");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2003-0279", "CVE-2003-0318", "CVE-2004-0266", "CVE-2004-0269");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("FreeBSD Ports: phpnuke");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: phpnuke

CVE-2003-0279
Multiple SQL injection vulnerabilities in the Web_Links module for
PHP-Nuke 5.x through 6.5 allows remote attackers to steal sensitive
information via numeric fields, as demonstrated using (1) the viewlink
function and cid parameter, or (2) index.php.

CVE-2003-0318
Cross-site scripting (XSS) vulnerability in the Statistics module for
PHP-Nuke 6.0 and earlier allows remote attackers to insert arbitrary
web script via the year parameter.

CVE-2004-0266
SQL injection vulnerability in the 'public message' capability
(public_message) for Php-Nuke 6.x to 7.1.0 allows remote attackers
obtain the administrator password via the c_mid parameter.

CVE-2004-0269
SQL injection vulnerability in PHP-Nuke 6.9 and earlier, and possibly
7.x, allows remote attackers to inject arbitrary SQL code and gain
sensitive information via (1) the category variable in the Search
module or (2) the admin variable in the Web_Links module.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.waraxe.us/index.php?modname=sa&id=27");
  script_xref(name:"URL", value:"http://secunia.com/advisories/11920");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/33ab4a47-bfc1-11d8-b00e-000347a4fa7d.html");

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

bver = portver(pkg:"phpnuke");
if(!isnull(bver) && revcomp(a:bver, b:"7.3")<0) {
  txt += 'Package phpnuke version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
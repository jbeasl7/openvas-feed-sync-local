# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52160");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-0544");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("FreeBSD Ports: phpmyadmin, phpMyAdmin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  phpmyadmin
   phpMyAdmin

CVE-2005-0544
phpMyAdmin 2.6.1 allows remote attackers to obtain the full path of
the server via direct requests to (1) sqlvalidator.lib.php, (2)
sqlparser.lib.php, (3) select_theme.lib.php, (4) select_lang.lib.php,
(5) relation_cleanup.lib.php, (6) header_meta_style.inc.php, (7)
get_foreign.lib.php, (8) display_tbl_links.lib.php, (9)
display_export.lib.php, (10) db_table_exists.lib.php, (11)
charset_conversion.lib.php, (12) ufpdf.php, (13) mysqli.dbi.lib.php,
(14) setup.php, or (15) cookie.auth.lib.php, which reveals the path in
a PHP error message.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7963");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/a7062952-9023-11d9-a22c-0001020eed82.html");

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

bver = portver(pkg:"phpmyadmin");
if(!isnull(bver) && revcomp(a:bver, b:"2.6.1.2")<0) {
  txt += 'Package phpmyadmin version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"phpMyAdmin");
if(!isnull(bver) && revcomp(a:bver, b:"2.6.1.2")<0) {
  txt += 'Package phpMyAdmin version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
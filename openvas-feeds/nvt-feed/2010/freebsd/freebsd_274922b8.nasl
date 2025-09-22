# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68003");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-10-10 19:35:00 +0200 (Sun, 10 Oct 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-3056");
  script_name("FreeBSD Ports: phpMyAdmin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  phpMyAdmin
   phpMyAdmin211

CVE-2010-3056
Multiple cross-site scripting (XSS) vulnerabilities in phpMyAdmin
2.11.x before 2.11.10.1 and 3.x before 3.3.5.1 allow remote attackers
to inject arbitrary web script or HTML via vectors related to (1)
db_search.php, (2) db_sql.php, (3) db_structure.php, (4)
js/messages.php, (5) libraries/common.lib.php, (6)
libraries/database_interface.lib.php, (7)
libraries/dbi/mysql.dbi.lib.php, (8) libraries/dbi/mysqli.dbi.lib.php,
(9) libraries/db_info.inc.php, (10) libraries/sanitizing.lib.php, (11)
libraries/sqlparser.lib.php, (12) server_databases.php, (13)
server_privileges.php, (14) setup/config.php, (15) sql.php, (16)
tbl_replace.php, and (17) tbl_sql.php.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2010-5.php");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/274922b8-ad20-11df-af1f-00e0814cab4e.html");

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

bver = portver(pkg:"phpMyAdmin");
if(!isnull(bver) && revcomp(a:bver, b:"3.3.5.1")<0) {
  txt += 'Package phpMyAdmin version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"phpMyAdmin211");
if(!isnull(bver) && revcomp(a:bver, b:"2.11.10.1")<0) {
  txt += 'Package phpMyAdmin211 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
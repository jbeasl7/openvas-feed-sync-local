# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52406");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0627", "CVE-2004-0628");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: mysql-server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: mysql-server

CVE-2004-0627
The check_scramble_323 function in MySQL 4.1.x before 4.1.3, and 5.0,
allows remote attackers to bypass authentication via a zero-length
scrambled string.

CVE-2004-0628
Stack-based buffer overflow in MySQL 4.1.x before 4.1.3, and 5.0,
allows remote attackers to cause a denial of service (crash) and
possibly execute arbitrary code via a long scramble string.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
software upgrades.");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.nextgenss.com/advisories/mysql-authbypass.txt");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/mysql/en/News-4.1.3.html");
  script_xref(name:"URL", value:"http://secunia.com/advisories/12020");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/vulnwatch/2004-q3/0003.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/e5e2883d-ceb9-11d8-8898-000d6111a684.html");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

txt = "";
vuln = FALSE;

bver = portver(pkg:"mysql-server");
if(!isnull(bver) && revcomp(a:bver, b:"4.1")>=0 && revcomp(a:bver, b:"4.1.3")<0) {
  txt += 'Package mysql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"5")>=0 && revcomp(a:bver, b:"5.0.0_2")<=0) {
  txt += 'Package mysql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
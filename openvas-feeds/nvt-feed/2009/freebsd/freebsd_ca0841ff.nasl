# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63630");
  script_version("2023-07-10T08:07:42+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:42 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-20 00:52:38 +0100 (Fri, 20 Mar 2009)");
  script_cve_id("CVE-2009-0542", "CVE-2009-0543");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: proftpd, proftpd-mysql");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  proftpd
   proftpd-mysql
   proftpd-devel

CVE-2009-0542
SQL injection vulnerability in ProFTPD Server 1.3.1 through 1.3.2rc2
allows remote attackers to execute arbitrary SQL commands via a '%'
(percent) character in the username, which introduces a ''' (single
quote) character during variable substitution by mod_sql.
CVE-2009-0543
ProFTPD Server 1.3.1, with NLS support enabled, allows remote
attackers to bypass SQL injection protection mechanisms via invalid,
encoded multibyte characters, which are not properly handled in (1)
mod_sql_mysql and (2) mod_sql_postgres.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/33842/");
  script_xref(name:"URL", value:"http://bugs.proftpd.org/show_bug.cgi?id=3173");
  script_xref(name:"URL", value:"http://bugs.proftpd.org/show_bug.cgi?id=3124");
  script_xref(name:"URL", value:"http://milw0rm.com/exploits/8037");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/ca0841ff-1254-11de-a964-0030843d3802.html");

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

bver = portver(pkg:"proftpd");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.2")<0) {
  txt += 'Package proftpd version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"proftpd-mysql");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.2")<0) {
  txt += 'Package proftpd-mysql version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"proftpd-devel");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.20080922")<=0) {
  txt += 'Package proftpd-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
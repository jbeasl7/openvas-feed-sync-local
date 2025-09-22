# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52185");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-0247");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_name("FreeBSD Ports: postgresql, postgresql-server, ja-postgresql");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  postgresql
   postgresql-server
   ja-postgresql

CVE-2005-0247
Multiple buffer overflows in gram.y for PostgreSQL 8.0.1 and earlier
may allow attackers to execute arbitrary code via (1) a large number
of variables in a SQL statement being handled by the
read_sql_construct function, (2) a large number of INTO variables in a
SELECT statement being handled by the make_select_stmt function, (3) a
large number of arbitrary variables in a SELECT statement being
handled by the make_select_stmt function, and (4) a large number of
INTO variables in a FETCH statement being handled by the
make_fetch_stmt function, a different set of vulnerabilities than
CVE-2005-0245.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://archives.postgresql.org/pgsql-committers/2005-02/msg00049.php");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/6b4b0b3f-8127-11d9-a9e7-0001020eed82.html");

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

bver = portver(pkg:"postgresql");
if(!isnull(bver) && revcomp(a:bver, b:"7.3.9_1")<0) {
  txt += 'Package postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"7.4")>0 && revcomp(a:bver, b:"7.4.7_1")<0) {
  txt += 'Package postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"8")>0 && revcomp(a:bver, b:"8.0.1_1")<0) {
  txt += 'Package postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"postgresql-server");
if(!isnull(bver) && revcomp(a:bver, b:"7.3.9_1")<0) {
  txt += 'Package postgresql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"7.4")>0 && revcomp(a:bver, b:"7.4.7_1")<0) {
  txt += 'Package postgresql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"8")>0 && revcomp(a:bver, b:"8.0.1_1")<0) {
  txt += 'Package postgresql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ja-postgresql");
if(!isnull(bver) && revcomp(a:bver, b:"7.3.9_1")<0) {
  txt += 'Package ja-postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"7.4")>0 && revcomp(a:bver, b:"7.4.7_1")<0) {
  txt += 'Package ja-postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"8")>0 && revcomp(a:bver, b:"8.0.1_1")<0) {
  txt += 'Package ja-postgresql version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
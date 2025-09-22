# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52158");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-0709", "CVE-2005-0710", "CVE-2005-0711");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12781");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: mysql-server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_xref(name:"URL", value:"https://www.vuxml.org/freebsd/619ef337-949a-11d9-b813-00d05964249f.html");
  script_tag(name:"insight", value:"The following package is affected: mysql-server

CVE-2005-0709
MySQL 4.0.23 and earlier, and 4.1.x up to 4.1.10, allows remote
authenticated users with INSERT and DELETE privileges to execute
arbitrary code by using CREATE FUNCTION to access libc calls, as
demonstrated byusing strcat, on_exit, and exit.

CVE-2005-0710
MySQL 4.0.23 and earlier, and 4.1.x up to 4.1.10, allows remote
authenticated users with INSERT and DELETE privileges to bypass
library path restrictions and execute arbitrary libraries by using
INSERT INTO to modify the mysql.func table, which is processed by the
udf_init function.

CVE-2005-0711
MySQL 4.0.23 and earlier, and 4.1.x up to 4.1.10, uses predictable
file names when creating temporary tables, which allows local users
with CREATE TEMPORARY TABLE privileges to overwrite arbitrary files
via a symlink attack.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

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

bver = portver(pkg:"mysql-server");
if(!isnull(bver) && revcomp(a:bver, b:"4.0.0")>=0 && revcomp(a:bver, b:"4.0.24")<0) {
  txt += 'Package mysql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"4.1.0")>=0 && revcomp(a:bver, b:"4.1.10a")<0) {
  txt += 'Package mysql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}

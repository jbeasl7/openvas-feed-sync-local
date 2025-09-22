# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56889");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-2742", "CVE-2006-2743");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: drupal");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: drupal

CVE-2006-2742
SQL injection vulnerability in Drupal 4.6.x before 4.6.7 and 4.7.0
allows remote attackers to execute arbitrary SQL commands via the (1)
count and (2) from variables to (a) database.mysql.inc, (b)
database.pgsql.inc, and (c) database.mysqli.inc.

CVE-2006-2743
Drupal 4.6.x before 4.6.7 and 4.7.0, when running on Apache with
mod_mime, does not properly handle files with multiple extensions,
which allows remote attackers to upload, modify, or execute arbitrary
files in the files directory.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://drupal.org/node/65357");
  script_xref(name:"URL", value:"http://drupal.org/node/65409");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/40a0185f-ec32-11da-be02-000c6ec775d9.html");

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

bver = portver(pkg:"drupal");
if(!isnull(bver) && revcomp(a:bver, b:"4.6.7")<0) {
  txt += 'Package drupal version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
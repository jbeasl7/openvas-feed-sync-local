# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60022");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2007-6299");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: drupal5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  drupal5
   drupal4

CVE-2007-6299
Multiple SQL injection vulnerabilities in Drupal and vbDrupal 4.7.x
before 4.7.9 and 5.x before 5.4 allow remote attackers to execute
arbitrary SQL commands via modules that pass input to the
taxonomy_select_nodes function, as demonstrated by the (1)
taxonomy_menu, (2) ajaxLoader, and (3) ubrowser contributed modules.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://drupal.org/node/198162");
  script_xref(name:"URL", value:"http://secunia.com/advisories/27932/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/fa708908-a8c7-11dc-b41d-000fb5066b20.html");

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

bver = portver(pkg:"drupal5");
if(!isnull(bver) && revcomp(a:bver, b:"5.4")<0) {
  txt += 'Package drupal5 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"drupal4");
if(!isnull(bver) && revcomp(a:bver, b:"4.7.9")<0) {
  txt += 'Package drupal4 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
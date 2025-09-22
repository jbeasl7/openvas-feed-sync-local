# SPDX-FileCopyrightText: 2011 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68829");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-3710");
  script_name("FreeBSD Ports: php5-filter");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  php5-filter
   php52-filter

CVE-2010-3710
Stack consumption vulnerability in the filter_var function in PHP
5.2.x through 5.2.14 and 5.3.x through 5.3.3, when
FILTER_VALIDATE_EMAIL mode is used, allows remote attackers to cause a
denial of service (memory consumption and application crash) via a
long e-mail address string.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.php.net/releases/5_3_4.php");
  script_xref(name:"URL", value:"http://www.php.net/releases/5_2_15.php");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/c623f058-10e7-11e0-becc-0022156e8794.html");

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

bver = portver(pkg:"php5-filter");
if(!isnull(bver) && revcomp(a:bver, b:"5.3.4")<0) {
  txt += 'Package php5-filter version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"php52-filter");
if(!isnull(bver) && revcomp(a:bver, b:"5.2.15")<0) {
  txt += 'Package php52-filter version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
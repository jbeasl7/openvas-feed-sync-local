# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54200");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-0869", "CVE-2005-0870");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("FreeBSD Ports: phpSysInfo");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: phpSysInfo

CVE-2005-0869
phpSysInfo 2.3 allows remote attackers to obtain sensitive information
via a direct request to (1) class.OpenBSD.inc.php, (2)
class.NetBSD.inc.php, (3) class.FreeBSD.inc.php, (4)
class.Darwin.inc.php, (5) XPath.class.php, (6) system_header.php, or
(7) system_footer.php, which reveal the path in a PHP error message.

CVE-2005-0870
Multiple cross-site scripting (XSS) vulnerabilities in phpSysInfo 2.3,
when register_globals is enabled, allow remote attackers to inject
arbitrary web script or HTML via the (1) sensor_program parameter to
index.php, (2) text[language], (3) text[template], or (4)
hide_picklist parameter to system_footer.php.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=111161017209422");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12887");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/50457509-d05e-11d9-9aed-000e0c2e438a.html");

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

bver = portver(pkg:"phpSysInfo");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package phpSysInfo version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
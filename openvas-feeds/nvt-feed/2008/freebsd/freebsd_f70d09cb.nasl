# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57065");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-0871", "CVE-2006-1794", "CVE-2006-3262", "CVE-2006-3263");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: mambo");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: mambo

CVE-2006-3262
SQL injection vulnerability in the Weblinks module (weblinks.php) in
Mambo 4.6rc1 and earlier allows remote attackers to execute arbitrary
SQL commands via the title parameter.

CVE-2006-3263
SQL injection vulnerability in the Weblinks module (weblinks.php) in
Mambo 4.6rc1 and earlier allows remote attackers to execute arbitrary
SQL commands via the catid parameter.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/20745/");
  script_xref(name:"URL", value:"http://www.mamboserver.com/?option=com_content&task=view&id=207");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=115056811230529");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/f70d09cb-0c46-11db-aac7-000c6ec775d9.html");

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

bver = portver(pkg:"mambo");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package mambo version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52273");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0836");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: mysql-server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:
   mysql-server
   mysql-client

CVE-2004-0836
Buffer overflow in the mysql_real_connect function in MySQL 4.x before
4.0.21, and 3.x before 3.23.49, allows remote attackers to cause a
denial of service and possibly execute arbitrary code via a malicious
DNS server.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
software upgrades.");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://bugs.mysql.com/bug.php?id=4017");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10981");
  script_xref(name:"URL", value:"http://lists.mysql.com/internals/14726");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2004-611.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/835256b8-46ed-11d9-8ce0-00065be4b5b6.html");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

txt = "";
vuln = FALSE;

bver = portver(pkg:"mysql-server");
if(!isnull(bver) && revcomp(a:bver, b:"3.23.58_3")<=0) {
  txt += 'Package mysql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"4")>=0 && revcomp(a:bver, b:"4.0.21")<0) {
  txt += 'Package mysql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mysql-client");
if(!isnull(bver) && revcomp(a:bver, b:"3.23.58_3")<=0) {
  txt += 'Package mysql-client version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"4")>=0 && revcomp(a:bver, b:"4.0.21")<0) {
  txt += 'Package mysql-client version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
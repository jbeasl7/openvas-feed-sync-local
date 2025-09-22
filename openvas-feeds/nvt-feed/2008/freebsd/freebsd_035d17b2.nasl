# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52274");
  script_version("2023-07-26T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:08 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0835");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: mysql-server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: mysql-server

CVE-2004-0835
MySQL 3.x before 3.23.59, 4.x before 4.0.19, 4.1.x before 4.1.2, and
5.x before 5.0.1, checks the CREATE/INSERT rights of the original
table instead of the target table in an ALTER TABLE RENAME operation,
which could allow attackers to conduct unauthorized activities.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://bugs.mysql.com/bug.php?id=3270");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11357");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2004-611.html");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/17666");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/035d17b2-484a-11d9-813c-00065be4b5b6.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"3.23.58_3")<=0) {
  txt += 'Package mysql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"4")>=0 && revcomp(a:bver, b:"4.0.21")<0) {
  txt += 'Package mysql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
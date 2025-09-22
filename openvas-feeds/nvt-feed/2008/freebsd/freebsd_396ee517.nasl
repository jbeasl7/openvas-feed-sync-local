# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52145");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-0961");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("FreeBSD Ports: horde, horde-php5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  horde
   horde-php5

CVE-2005-0961
Cross-site scripting (XSS) vulnerability in Horde 3.0.4 before
3.0.4-RC2 allows remote attackers to inject arbitrary web script or
HTML via the parent frame title.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://cvs.horde.org/diff.php/horde/docs/CHANGES?r1=1.515.2.49&r2=1.515.2.93&ty=h");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12943");
  script_xref(name:"URL", value:"http://lists.horde.org/archives/announce/2005/000176.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/396ee517-a607-11d9-ac72-000bdb1444a4.html");

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

bver = portver(pkg:"horde");
if(!isnull(bver) && revcomp(a:bver, b:"3")>0 && revcomp(a:bver, b:"3.0.4")<0) {
  txt += 'Package horde version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"horde-php5");
if(!isnull(bver) && revcomp(a:bver, b:"3")>0 && revcomp(a:bver, b:"3.0.4")<0) {
  txt += 'Package horde-php5 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
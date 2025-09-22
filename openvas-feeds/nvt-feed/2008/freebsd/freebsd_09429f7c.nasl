# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56973");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-2195");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: horde, horde-php5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  horde
   horde-php5

CVE-2006-2195
Cross-site scripting (XSS) vulnerability in horde 3 (horde3) before
3.1.1 allows remote attackers to inject arbitrary web script or HTML
via unknown vectors.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2006/2356");
  script_xref(name:"URL", value:"http://cvs.horde.org/diff.php?f=horde%2Ftest.php&r1=1.145&r2=1.146");
  script_xref(name:"URL", value:"http://cvs.horde.org/diff.php?f=horde%2Ftemplates%2Fproblem%2Fproblem.inc&r1=2.25&r2=2.26");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/09429f7c-fd6e-11da-b1cd-0050bf27ba24.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"3.1.1")<=0) {
  txt += 'Package horde version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"horde-php5");
if(!isnull(bver) && revcomp(a:bver, b:"3.1.1")<=0) {
  txt += 'Package horde-php5 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
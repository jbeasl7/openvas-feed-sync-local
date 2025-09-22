# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57747");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-6772");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: w3m, w3m-img, w3m-m17n, w3m-m17n-img, ja-w3m, ja-w3m-img");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  w3m w3m-img w3m-m17n w3m-m17n-img ja-w3m ja-w3m-img");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://sourceforge.net/tracker/index.php?func=detail&aid=1612792&group_id=39518&atid=425439");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/21735");
  script_xref(name:"URL", value:"http://secunia.com/advisories/23492/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/9347d82d-9a66-11db-b271-000e35248ad7.html");

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

bver = portver(pkg:"w3m");
if(!isnull(bver) && revcomp(a:bver, b:"0.5.1_6")<0) {
  txt += 'Package w3m version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"w3m-img");
if(!isnull(bver) && revcomp(a:bver, b:"0.5.1_6")<0) {
  txt += 'Package w3m-img version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"w3m-m17n");
if(!isnull(bver) && revcomp(a:bver, b:"0.5.1_6")<0) {
  txt += 'Package w3m-m17n version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"w3m-m17n-img");
if(!isnull(bver) && revcomp(a:bver, b:"0.5.1_6")<0) {
  txt += 'Package w3m-m17n-img version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ja-w3m");
if(!isnull(bver) && revcomp(a:bver, b:"0.5.1_6")<0) {
  txt += 'Package ja-w3m version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ja-w3m-img");
if(!isnull(bver) && revcomp(a:bver, b:"0.5.1_6")<0) {
  txt += 'Package ja-w3m-img version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
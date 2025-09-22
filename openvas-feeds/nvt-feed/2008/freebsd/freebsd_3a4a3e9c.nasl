# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61799");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-11-01 01:55:10 +0100 (Sat, 01 Nov 2008)");
  script_cve_id("CVE-2008-4796");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: wordpress, de-wordpress, wordpress-mu");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  wordpress
   de-wordpress
   wordpress-mu");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/Advisories/32361/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31887");
  script_xref(name:"URL", value:"http://wordpress.org/development/2008/10/wordpress-263/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/3a4a3e9c-a1fe-11dd-81be-001c2514716c.html");

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

bver = portver(pkg:"wordpress");
if(!isnull(bver) && revcomp(a:bver, b:"2.6.3")<0) {
  txt += 'Package wordpress version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"de-wordpress");
if(!isnull(bver) && revcomp(a:bver, b:"2.6.3")<0) {
  txt += 'Package de-wordpress version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"wordpress-mu");
if(!isnull(bver) && revcomp(a:bver, b:"2.6.3")<0) {
  txt += 'Package wordpress-mu version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52232");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-1267");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_name("FreeBSD Ports: cups-base, fr-cups-base");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  cups-base
   fr-cups-base

CVE-2004-1267
Buffer overflow in the ParseCommand function in hpgl-input.c in the
hpgltops program for CUPS 1.1.22 allows remote attackers to execute
arbitrary code via a crafted HPGL file.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://tigger.uic.edu/~jlongs2/holes/cups.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11968");
  script_xref(name:"URL", value:"http://www.cups.org/str.php?L1024");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/40a3bca2-6809-11d9-a9e7-0001020eed82.html");

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

bver = portver(pkg:"cups-base");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.22.0_2")<0) {
  txt += 'Package cups-base version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"fr-cups-base");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.22.0_2")<0) {
  txt += 'Package fr-cups-base version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55907");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0967");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11285");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: ghostscript-gnu, ghostscript-gnu-nox11");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_xref(name:"URL", value:"https://www.vuxml.org/freebsd/27a70a01-5f6c-11da-8d54-000cf18bbe54.html");
  script_tag(name:"insight", value:"The following packages are affected:

  ghostscript-gnu
   ghostscript-gnu-nox11
   ghostscript-afpl
   ghostscript-afpl-nox11

CVE-2004-0967
The (1) pj-gs.sh, (2) ps2epsi, (3) pv.sh, and (4) sysvlp.sh scripts
in the ESP Ghostscript (espgs) package in Trustix Secure Linux 1.5
through 2.1, and other operating systems, allow local users to
overwrite files via a symlink attack on temporary files.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

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

bver = portver(pkg:"ghostscript-gnu");
if(!isnull(bver) && revcomp(a:bver, b:"7.07_14")<0) {
  txt += 'Package ghostscript-gnu version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ghostscript-gnu-nox11");
if(!isnull(bver) && revcomp(a:bver, b:"7.07_14")<0) {
  txt += 'Package ghostscript-gnu-nox11 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ghostscript-afpl");
if(!isnull(bver) && revcomp(a:bver, b:"8.53_1")<0) {
  txt += 'Package ghostscript-afpl version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ghostscript-afpl-nox11");
if(!isnull(bver) && revcomp(a:bver, b:"8.53_1")<0) {
  txt += 'Package ghostscript-afpl-nox11 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}

# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56317");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-2972");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: koffice");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  koffice
   abiword

CVE-2005-2972
Multiple stack-based buffer overflows in the RTF import feature in
AbiWord before 2.2.11 allow user-complicit attackers to execute
arbitrary code via an RTF file with long identifiers, which are not
properly handled in the (1) ParseLevelText, (2) getCharsInsideBrace,
(3) HandleLists, (4) or (5) HandleAbiLists functions in
ie_imp_RTF.cpp, a different vulnerability than CVE-2005-2964.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://scary.beasts.org/security/CESA-2005-006.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15096");
  script_xref(name:"URL", value:"http://www.abisource.com/changelogs/2.2.11.phtml");
  script_xref(name:"URL", value:"http://www.kde.org/info/security/advisory-20051011-1.txt");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/9cd52bc6-a213-11da-b410-000e0c2e438a.html");

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

bver = portver(pkg:"koffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.2.0")>0 && revcomp(a:bver, b:"1.4.1_1,1")<0) {
  txt += 'Package koffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"abiword");
if(!isnull(bver) && revcomp(a:bver, b:"2.2.11")<0) {
  txt += 'Package abiword version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
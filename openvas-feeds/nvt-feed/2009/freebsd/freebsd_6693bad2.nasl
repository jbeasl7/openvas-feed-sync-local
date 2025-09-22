# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66154");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-11-11 15:56:44 +0100 (Wed, 11 Nov 2009)");
  script_cve_id("CVE-2009-3628", "CVE-2009-3629", "CVE-2009-3630", "CVE-2009-3631", "CVE-2009-3632", "CVE-2009-3633", "CVE-2009-3634", "CVE-2009-3635", "CVE-2009-3636");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_name("FreeBSD Ports: typo3");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: typo3

CVE-2009-3628
The Backend subcomponent in TYPO3 4.0.13 and earlier, 4.1.x before
4.1.13, 4.2.x before 4.2.10, and 4.3.x before 4.3beta2 allows remote
authenticated users to determine an encryption key via crafted input
to a tt_content form element.

CVE-2009-3629
Multiple cross-site scripting (XSS) vulnerabilities in the Backend
subcomponent in TYPO3 4.0.13 and earlier, 4.1.x before 4.1.13, 4.2.x
before 4.2.10, and 4.3.x before 4.3beta2 allow remote authenticated
users to inject arbitrary web script or HTML via unspecified vectors.

CVE-2009-3630
The Backend subcomponent in TYPO3 4.0.13 and earlier, 4.1.x before
4.1.13, 4.2.x before 4.2.10, and 4.3.x before 4.3beta2 allows remote
authenticated users to place arbitrary web sites in TYPO3 backend
framesets via crafted parameters, related to a 'frame hijacking'
issue.

CVE-2009-3631
The Backend subcomponent in TYPO3 4.0.13 and earlier, 4.1.x before
4.1.13, 4.2.x before 4.2.10, and 4.3.x before 4.3beta2, when the DAM
extension or ftp upload is enabled, allows remote authenticated users
to execute arbitrary commands via shell metacharacters in a filename.

CVE-2009-3632
SQL injection vulnerability in the traditional frontend editing
feature in the Frontend Editing subcomponent in TYPO3 4.0.13 and
earlier, 4.1.x before 4.1.13, 4.2.x before 4.2.10, and 4.3.x before
4.3beta2 allows remote authenticated users to execute arbitrary SQL
commands via unspecified parameters.

CVE-2009-3633
Cross-site scripting (XSS) vulnerability in the
t3lib_div::quoteJSvalue API function in TYPO3 4.0.13 and earlier,
4.1.x before 4.1.13, 4.2.x before 4.2.10, and 4.3.x before 4.3beta2
allows remote attackers to inject arbitrary web script or HTML via
unspecified vectors related to the sanitizing algorithm.

CVE-2009-3634
Cross-site scripting (XSS) vulnerability in the Frontend Login Box
(aka felogin) subcomponent in TYPO3 4.2.0 through 4.2.6 allows remote
attackers to inject arbitrary web script or HTML via unspecified
parameters.

CVE-2009-3635
The Install Tool subcomponent in TYPO3 4.0.13 and earlier, 4.1.x
before 4.1.13, 4.2.x before 4.2.10, and 4.3.x before 4.3beta2 allows
remote attackers to gain access by using only the password's md5 hash
as a credential.

CVE-2009-3636
Cross-site scripting (XSS) vulnerability in the Install Tool
subcomponent in TYPO3 4.0.13 and earlier, 4.1.x before 4.1.13, 4.2.x
before 4.2.10, and 4.3.x before 4.3beta2 allows remote attackers to
inject arbitrary web script or HTML via unspecified parameters.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://typo3.org/teams/security/security-bulletins/typo3-sa-2009-016/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36801");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37122/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/6693bad2-ca50-11de-8ee8-00215c6a37bb.html");

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

bver = portver(pkg:"typo3");
if(!isnull(bver) && revcomp(a:bver, b:"4.2.10")<0) {
  txt += 'Package typo3 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
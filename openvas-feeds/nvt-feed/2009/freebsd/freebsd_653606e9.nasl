# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63361");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
  script_cve_id("CVE-2009-0255", "CVE-2009-0256", "CVE-2009-0257", "CVE-2009-0258");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-14 16:10:04 +0000 (Wed, 14 Feb 2024)");
  script_name("FreeBSD Ports: typo3");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: typo3

CVE-2009-0255
The System extension Install tool in TYPO3 4.0.0 through 4.0.9, 4.1.0
through 4.1.7, and 4.2.0 through 4.2.3 creates the encryption key with
an insufficiently random seed, which makes it easier for attackers to
crack the key.

CVE-2009-0256
Session fixation vulnerability in the authentication library in TYPO3
4.0.0 through 4.0.9, 4.1.0 through 4.1.7, and 4.2.0 through 4.2.3
allows remote attackers to hijack web sessions via unspecified vectors
related to (1) frontend and (2) backend authentication.

CVE-2009-0257
Multiple cross-site scripting (XSS) vulnerabilities in TYPO3 4.0.0
through 4.0.9, 4.1.0 through 4.1.7, and 4.2.0 through 4.2.3 allow
remote attackers to inject arbitrary web script or HTML via the (1)
name and (2) content of indexed files to the (a) Indexed Search Engine
(indexed_search) system extension, (b) unspecified test scripts in the
ADOdb system extension, and (c) unspecified vectors in the Workspace
module.

CVE-2009-0258
The Indexed Search Engine (indexed_search) system extension in TYPO3
4.0.0 through 4.0.9, 4.1.0 through 4.1.7, and 4.2.0 through 4.2.3
allows remote attackers to execute arbitrary commands via a crafted
filename containing shell metacharacters, which is not properly
handled by the command-line indexer.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/33617/");
  script_xref(name:"URL", value:"http://typo3.org/teams/security/security-bulletins/typo3-sa-2009-001/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/653606e9-f6ac-11dd-94d9-0030843d3802.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"4.2.4")<0) {
  txt += 'Package typo3 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
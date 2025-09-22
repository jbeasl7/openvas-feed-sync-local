# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70746");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2011-2462", "CVE-2011-1353", "CVE-2011-2431", "CVE-2011-2432", "CVE-2011-2433", "CVE-2011-2434", "CVE-2011-2435", "CVE-2011-2436", "CVE-2011-2437", "CVE-2011-2438", "CVE-2011-2439", "CVE-2011-2440", "CVE-2011-2441", "CVE-2011-2442");
  script_version("2024-07-01T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-07-01 05:05:38 +0000 (Mon, 01 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-28 14:21:09 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2012-02-12 07:27:20 -0500 (Sun, 12 Feb 2012)");
  script_name("FreeBSD Ports: acroread9");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: acroread9

CVE-2011-2462
Unspecified vulnerability in the U3D component in Adobe Reader and
Acrobat 10.1.1 and earlier on Windows and Mac OS X, and Adobe Reader
9.x through 9.4.6 on UNIX, allows remote attackers to execute
arbitrary code or cause a denial of service (memory corruption) via
unknown vectors, as exploited in the wild in December 2011.

CVE-2011-1353
Unspecified vulnerability in Adobe Reader 10.x before 10.1.1 on
Windows allows local users to gain privileges via unknown vectors.

CVE-2011-2431
Adobe Reader and Acrobat 8.x before 8.3.1, 9.x before 9.4.6, and 10.x
before 10.1.1 allow attackers to execute arbitrary code via
unspecified vectors, related to a 'security bypass vulnerability.'

CVE-2011-2432
Buffer overflow in the U3D TIFF Resource in Adobe Reader and Acrobat
8.x before 8.3.1, 9.x before 9.4.6, and 10.x before 10.1.1 allows
attackers to execute arbitrary code via unspecified vectors.

CVE-2011-2433
Heap-based buffer overflow in Adobe Reader and Acrobat 8.x before
8.3.1, 9.x before 9.4.6, and 10.x before 10.1.1 allows attackers to
execute arbitrary code via unspecified vectors, a different
vulnerability than CVE-2011-2434 and CVE-2011-2437.

CVE-2011-2434
Heap-based buffer overflow in Adobe Reader and Acrobat 8.x before
8.3.1, 9.x before 9.4.6, and 10.x before 10.1.1 allows attackers to
execute arbitrary code via unspecified vectors, a different
vulnerability than CVE-2011-2433 and CVE-2011-2437.

Text truncated. Please see the references for more information.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-24.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/advisories/apsa11-04.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/fa2f386f-4814-11e1-89b4-001ec9578670.html");

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

bver = portver(pkg:"acroread9");
if(!isnull(bver) && revcomp(a:bver, b:"9.4.7")<0) {
  txt += 'Package acroread9 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
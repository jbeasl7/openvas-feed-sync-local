# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56515");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-1614", "CVE-2006-1615", "CVE-2006-1630");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: clamav");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  clamav
   clamav-devel

CVE-2006-1614
Integer overflow in the cli_scanpe function in the PE header parser
(libclamav/pe.c) in Clam AntiVirus (ClamAV) before 0.88.1, when
ArchiveMaxFileSize is disabled, allows remote attackers to cause a
denial of service and possibly execute arbitrary code.

CVE-2006-1615
Multiple format string vulnerabilities in the logging code in Clam
AntiVirus (ClamAV) before 0.88.1 might allow remote attackers to
execute arbitrary code.  NOTE: as of 20060410, it is unclear whether
this is a vulnerability, as there is some evidence that the arguments
are actually being sanitized properly.

CVE-2006-1630
The cli_bitset_set function in libclamav/others.c in Clam AntiVirus
(ClamAV) before 0.88.1 allows remote attackers to cause a denial of
service via unspecified vectors that trigger an 'invalid memory
access.'");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/19534/");
  script_xref(name:"URL", value:"http://www.us.debian.org/security/2006/dsa-1024");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/6a5174bd-c580-11da-9110-00123ffe8333.html");

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

bver = portver(pkg:"clamav");
if(!isnull(bver) && revcomp(a:bver, b:"0.88.1")<0) {
  txt += 'Package clamav version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"clamav-devel");
if(!isnull(bver) && revcomp(a:bver, b:"20051104_1")<=0) {
  txt += 'Package clamav-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
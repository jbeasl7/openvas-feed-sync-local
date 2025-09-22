# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61920");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-11-24 23:46:43 +0100 (Mon, 24 Nov 2008)");
  script_cve_id("CVE-2008-3863", "CVE-2008-4306");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: enscript-a4, enscript-letter, enscript-letterdj");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  enscript-a4
   enscript-letter
   enscript-letterdj

CVE-2008-3863
Stack-based buffer overflow in the read_special_escape function in
src/psgen.c in GNU Enscript 1.6.1 and 1.6.4 beta, when the -e (aka
special escapes processing) option is enabled, allows user-assisted
remote attackers to execute arbitrary code via a crafted ASCII file,
related to the setfilename command.
CVE-2008-4306
Unspecified vulnerability in enscript before 1.6.4 in Ubuntu Linux
6.06 LTS, 7.10, 8.04 LTS, and 8.10 has unknown impact and attack
vectors, possibly related to a buffer overflow.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2008-41/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/a1126054-b57c-11dd-8892-0017319806e7.html");

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

bver = portver(pkg:"enscript-a4");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.4_2")<0) {
  txt += 'Package enscript-a4 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"enscript-letter");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.4_2")<0) {
  txt += 'Package enscript-letter version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"enscript-letterdj");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.4_2")<0) {
  txt += 'Package enscript-letterdj version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
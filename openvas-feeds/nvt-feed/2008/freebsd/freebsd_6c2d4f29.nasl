# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52130");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-1099", "CVE-2005-1100");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: gld");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: gld

CVE-2005-1099
Multiple buffer overflows in the HandleChild function in server.c in
Greylisting daemon (GLD) 1.3 and 1.4, when GLD is listening on a
network interface, allow remote attackers to execute arbitrary code.

CVE-2005-1100
Format string vulnerability in the ErrorLog function in cnf.c in
Greylisting daemon (GLD) 1.3 and 1.4 allows remote attackers to
execute arbitrary code via format string specifiers in data that is
passed directly to syslog.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=111339935903880");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13129");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13133");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=111342432325670");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/6c2d4f29-af3e-11d9-837d-000e0c2e438a.html");

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

bver = portver(pkg:"gld");
if(!isnull(bver) && revcomp(a:bver, b:"1.5")<0) {
  txt += 'Package gld version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
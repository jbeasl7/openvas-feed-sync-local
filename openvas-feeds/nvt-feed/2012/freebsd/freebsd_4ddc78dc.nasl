# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70585");
  script_tag(name:"creation_date", value:"2012-02-13 01:48:16 +0100 (Mon, 13 Feb 2012)");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-4862");
  script_version("2023-07-26T05:05:09+0000");
  script_name("FreeBSD Ports: krb5-appl");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: krb5-appl

CVE-2011-4862
Buffer overflow in libtelnet/encrypt.c in telnetd in FreeBSD 7.3
through 9.0, MIT Kerberos Version 5 Applications (aka krb5-appl) 1.0.2
and earlier, and Heimdal 1.5.1 and earlier allows remote attackers to
execute arbitrary code via a long encryption key, as exploited in the
wild in December 2011.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://security.FreeBSD.org/advisories/FreeBSD-SA-11:08.telnetd.asc");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/4ddc78dc-300a-11e1-a2aa-0016ce01e285.html");

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

bver = portver(pkg:"krb5-appl");
if(!isnull(bver) && revcomp(a:bver, b:"1.0.2_1")<0) {
  txt += 'Package krb5-appl version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
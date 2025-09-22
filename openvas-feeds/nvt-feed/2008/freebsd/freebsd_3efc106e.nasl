# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.62854");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-12-10 05:23:56 +0100 (Wed, 10 Dec 2008)");
  script_cve_id("CVE-2008-5301");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("FreeBSD Ports: dovecot-managesieve");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: dovecot-managesieve

CVE-2008-5301
Directory traversal vulnerability in the ManageSieve implementation in
Dovecot 1.0.15, 1.1, and 1.2 allows remote attackers to read and
modify arbitrary .sieve files via a '..' (dot dot) in a script name.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2008/3190");
  script_xref(name:"URL", value:"http://secunia.com/Advisories/32768/");
  script_xref(name:"URL", value:"http://dovecot.org/list/dovecot/2008-November/035259.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/3efc106e-c451-11dd-a721-0030843d3802.html");

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

bver = portver(pkg:"dovecot-managesieve");
if(!isnull(bver) && revcomp(a:bver, b:"0.10.4")<0) {
  txt += 'Package dovecot-managesieve version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"0.11.0")>=0 && revcomp(a:bver, b:"0.11.1")<0) {
  txt += 'Package dovecot-managesieve version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67293");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-04-21 03:31:17 +0200 (Wed, 21 Apr 2010)");
  script_cve_id("CVE-2010-1163");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: sudo");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: sudo

CVE-2010-1163
The command matching functionality in sudo 1.6.8 through 1.7.2p5 does
not properly handle when a file in the current working directory has
the same name as a pseudo-command in the sudoers file and the PATH
contains an entry for '.', which allows local users to execute
arbitrary commands via a Trojan horse executable, as demonstrated
using sudoedit, a different vulnerability than CVE-2010-0426.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.sudo.ws/pipermail/sudo-announce/2010-April/000093.html");
  script_xref(name:"URL", value:"http://www.sudo.ws/sudo/alerts/sudoedit_escalate2.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/1a9f678d-48ca-11df-85f8-000c29a67389.html");

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

bver = portver(pkg:"sudo");
if(!isnull(bver) && revcomp(a:bver, b:"1.7.2.6")<0) {
  txt += 'Package sudo version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
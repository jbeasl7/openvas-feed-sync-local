# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66644");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-01-07 13:59:33 +0100 (Thu, 07 Jan 2010)");
  script_cve_id("CVE-2009-4024", "CVE-2009-4025");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: pear-Net_Ping");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  pear-Net_Ping
   pear-Net_Traceroute

CVE-2009-4024
Argument injection vulnerability in the ping function in Ping.php in
the Net_Ping package before 2.4.5 for PEAR allows remote attackers to
execute arbitrary shell commands via the host parameter.

CVE-2009-4025
Argument injection vulnerability in the traceroute function in
Traceroute.php in the Net_Traceroute package before 0.21.2 for PEAR
allows remote attackers to execute arbitrary shell commands via the
host parameter.  NOTE: some of these details are obtained from third
party information.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://pear.php.net/advisory20091114-01.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37093");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37094");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/56ba8728-f987-11de-b28d-00215c6a37bb.html");

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

bver = portver(pkg:"pear-Net_Ping");
if(!isnull(bver) && revcomp(a:bver, b:"2.4.5")<0) {
  txt += 'Package pear-Net_Ping version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"pear-Net_Traceroute");
if(!isnull(bver) && revcomp(a:bver, b:"0.21.2")<0) {
  txt += 'Package pear-Net_Traceroute version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
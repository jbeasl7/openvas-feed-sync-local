# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56349");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-0705");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_name("FreeBSD Ports: ssh2, ssh2-nox11");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  ssh2
   ssh2-nox11

CVE-2006-0705
Format string vulnerability in a logging function as used by various
SFTP servers, including (1) AttachmateWRQ Reflection for Secure IT
UNIX Server before 6.0.0.9, (2) Reflection for Secure IT Windows
Server before 6.0 build 38, (3) F-Secure SSH Server for Windows before
5.3 build 35, (4) F-Secure SSH Server for UNIX 3.0 through 5.0.8, (5)
SSH Tectia Server 4.3.6 and earlier and 4.4.0, and (6) SSH Shell
Server 3.2.9 and earlier, allows remote authenticated users to execute
arbitrary commands via unspecified vectors, involving crafted
filenames and the stat command.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.ssh.com/company/newsroom/article/715/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/16640");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2006/0554");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1015619");
  script_xref(name:"URL", value:"http://secunia.com/advisories/18828");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/24651");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/594ad3c5-a39b-11da-926c-0800209adf0e.html");

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

bver = portver(pkg:"ssh2");
if(!isnull(bver) && revcomp(a:bver, b:"3.2.9.1_5")<0) {
  txt += 'Package ssh2 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ssh2-nox11");
if(!isnull(bver) && revcomp(a:bver, b:"3.2.9.1_5")<0) {
  txt += 'Package ssh2-nox11 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
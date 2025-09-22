# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67052");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-03-16 17:25:39 +0100 (Tue, 16 Mar 2010)");
  script_cve_id("CVE-2010-0426");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: sudo");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: sudo

CVE-2010-0426
sudo 1.6.x before 1.6.9p21 and 1.7.x before 1.7.2p4, when a
pseudo-command is enabled, permits a match between the name of the
pseudo-command and the name of an executable file in an arbitrary
directory, which allows local users to gain privileges via a crafted
executable file, as demonstrated by a file named sudoedit in a user's
home directory.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.sudo.ws/pipermail/sudo-announce/2010-February/000092.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38362");
  script_xref(name:"URL", value:"http://www.sudo.ws/sudo/alerts/sudoedit_escalate.html");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38659");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/018a84d0-2548-11df-b4a3-00e0815b8da8.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"1.7.2.4")<0) {
  txt += 'Package sudo version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
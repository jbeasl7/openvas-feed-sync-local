# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52254");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-1273", "CVE-2004-1274");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: greed");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: greed

CVE-2004-1273
Buffer overflow in the DownloadLoop function in main.c for greed 0.81p
allows remote attackers to execute arbitrary code via a GRX file
containing a long filename.

CVE-2004-1274
The DownloadLoop function in main.c for greed 0.81p allows remote
attackers to execute arbitrary code via a GRX file containing a
filename with shell metacharacters.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://tigger.uic.edu/~jlongs2/holes/greed.txt");
  script_xref(name:"URL", value:"http://secunia.com/advisories/13534/");
  script_xref(name:"URL", value:"http://marc.theaimsgroup.com/?l=bugtraq&m=110321888413132");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/bd579366-5290-11d9-ac20-00065be4b5b6.html");

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

bver = portver(pkg:"greed");
if(!isnull(bver) && revcomp(a:bver, b:"0.81p")<=0) {
  txt += 'Package greed version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52456");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2003-0744");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("FreeBSD Ports: leafnode");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: leafnode

CVE-2003-0744:
The fetchnews client in leafnode allows remote attackers
to cause a denial of service (process hang and termination)
via certain malformed Usenet news articles that cause
fetchnews to hang while waiting for input.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://leafnode.sourceforge.net/leafnode-SA-2002-01");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6490");
  script_xref(name:"URL", value:"http://sourceforge.net/mailarchive/message.php?msg_id=2796226");
  script_xref(name:"URL", value:"http://article.gmane.org/gmane.network.leafnode.announce/8");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/f7a3b18c-624c-4703-9756-b6b27429e5b0.html");

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

bver = portver(pkg:"leafnode");
if(!isnull(bver) && revcomp(a:bver, b:"1.9.20")>=0 && revcomp(a:bver, b:"1.9.30")<0) {
  txt += 'Package leafnode version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
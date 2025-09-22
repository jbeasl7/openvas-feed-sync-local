# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63280");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-01-26 18:18:20 +0100 (Mon, 26 Jan 2009)");
  script_cve_id("CVE-2008-3651", "CVE-2008-3652");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("FreeBSD Ports: ipsec-tools");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: ipsec-tools

CVE-2008-3651
Memory leak in racoon/proposal.c in the racoon daemon in ipsec-tools
before 0.7.1 allows remote authenticated users to cause a denial of
service (memory consumption) via invalid proposals.

CVE-2008-3652
src/racoon/handler.c in racoon in ipsec-tools does not remove an
'orphaned ph1' (phase 1) handle when it has been initiated remotely,
which allows remote attackers to cause a denial of service (resource
consumption).");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://marc.info/?l=ipsec-tools-devel&m=121688914101709&w=2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30657");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/abcacb5a-e7f1-11dd-afcd-00e0815b8da8.html");

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

bver = portver(pkg:"ipsec-tools");
if(!isnull(bver) && revcomp(a:bver, b:"0.7.1")<0) {
  txt += 'Package ipsec-tools version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
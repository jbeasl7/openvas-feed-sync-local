# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61873");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-11-19 16:52:57 +0100 (Wed, 19 Nov 2008)");
  script_cve_id("CVE-2008-4309");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("FreeBSD Ports: net-snmp");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  net-snmp
   net-snmp53

CVE-2008-4309
Integer overflow in the netsnmp_create_subtree_cache function in
agent/snmp_agent.c in net-snmp 5.4 before 5.4.2.1, 5.3 before 5.3.2.3,
and 5.2 before 5.2.5.1 allows remote attackers to cause a denial of
service (crash) via a crafted SNMP GETBULK request, which triggers a
heap-based buffer overflow, related to the number of responses or
repeats.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://sourceforge.net/forum/forum.php?forum_id=882903");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2008/10/31/1");
  script_xref(name:"URL", value:"http://net-snmp.svn.sourceforge.net/viewvc/net-snmp/tags/Ext-5-2-5-1/net-snmp/agent/snmp_agent.c?r1=17271&r2=17272&pathrev=17272");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/daf045d7-b211-11dd-a987-000c29ca8953.html");

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

bver = portver(pkg:"net-snmp");
if(!isnull(bver) && revcomp(a:bver, b:"5.4.2.1")<0) {
  txt += 'Package net-snmp version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"net-snmp53");
if(!isnull(bver) && revcomp(a:bver, b:"5.3.2.3")<0) {
  txt += 'Package net-snmp53 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
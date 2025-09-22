# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71518");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2012-3570", "CVE-2012-3571", "CVE-2012-3954");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)");
  script_name("FreeBSD Ports: isc-dhcp41-server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  isc-dhcp41-server
   isc-dhcp42-server

CVE-2012-3570
Buffer overflow in ISC DHCP 4.2.x before 4.2.4-P1, when DHCPv6 mode is
enabled, allows remote attackers to cause a denial of service
(segmentation fault and daemon exit) via a crafted client identifier
parameter.
CVE-2012-3571
ISC DHCP 4.1.2 through 4.2.4 and 4.1-ESV before 4.1-ESV-R6 allows
remote attackers to cause a denial of service (infinite loop and CPU
consumption) via a malformed client identifier.
CVE-2012-3954
Multiple memory leaks in ISC DHCP 4.1.x and 4.2.x before 4.2.4-P1 and
4.1-ESV before 4.1-ESV-R6 allow remote attackers to cause a denial of
service (memory consumption) by sending many requests.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-00714");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-00712");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-00737");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/c7fa3618-d5ff-11e1-90a2-000c299b62e1.html");

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

bver = portver(pkg:"isc-dhcp41-server");
if(!isnull(bver) && revcomp(a:bver, b:"4.1.e_5,2")<0) {
  txt += "Package isc-dhcp41-server version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"isc-dhcp42-server");
if(!isnull(bver) && revcomp(a:bver, b:"4.2.4_1")<0) {
  txt += "Package isc-dhcp42-server version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
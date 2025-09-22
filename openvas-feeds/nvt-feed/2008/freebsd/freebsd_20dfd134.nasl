# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52343");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0938", "CVE-2004-0960", "CVE-2004-0961");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("FreeBSD Ports: freeradius");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: freeradius

CVE-2004-0938
FreeRADIUS before 1.0.1 allows remote attackers to cause a denial of
service (server crash) by sending an Ascend-Send-Secret attribute
without the required leading packet.

CVE-2004-0960
FreeRADIUS before 1.0.1 allows remote attackers to cause a denial of
service (core dump) via malformed USR vendor-specific attributes (VSA)
that cause a memcpy operation with a -1 argument.

CVE-2004-0961
Memory leak in FreeRADIUS before 1.0.1 allows remote attackers to
cause a denial of service (memory exhaustion) via a series of
Access-Request packets with (1) Ascend-Send-Secret, (2)
Ascend-Recv-Secret, or (3) Tunnel-Password attributes.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.securitytracker.com/alerts/2004/Sep/1011364.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11222");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/20dfd134-1d39-11d9-9be9-000c6e8f12ef.html");

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

bver = portver(pkg:"freeradius");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.0")>=0 && revcomp(a:bver, b:"1.0.1")<0) {
  txt += 'Package freeradius version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
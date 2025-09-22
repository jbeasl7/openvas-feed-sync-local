# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64447");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
  script_cve_id("CVE-2009-0692");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: isc-dhcp31-client");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  isc-dhcp31-client
   isc-dhcp30-client

CVE-2009-0692
Stack-based buffer overflow in the  script_write_params method in
client/dhclient.c in ISC DHCP dhclient 4.1 before 4.1.0p1, 4.0 before
4.0.1p1, 3.1 before 3.1.2p1, 3.0, and 2.0 allows remote DHCP servers
to execute arbitrary code via a crafted subnet-mask option.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://www.isc.org/node/468");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35785");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/410676");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/c444c8b7-7169-11de-9ab7-000c29a67389.html");

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

bver = portver(pkg:"isc-dhcp31-client");
if(!isnull(bver) && revcomp(a:bver, b:"3.1.1")<=0) {
  txt += 'Package isc-dhcp31-client version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"isc-dhcp30-client");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.7")<=0) {
  txt += 'Package isc-dhcp30-client version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
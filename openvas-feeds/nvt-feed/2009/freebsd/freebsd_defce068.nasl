# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63966");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-11 20:24:31 +0200 (Mon, 11 May 2009)");
  script_cve_id("CVE-2009-1210", "CVE-2009-1268", "CVE-2009-1269");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: wireshark, wireshark-lite");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  wireshark
   wireshark-lite

CVE-2009-1210
Format string vulnerability in the PROFINET/DCP (PN-DCP) dissector in
Wireshark 1.0.6 and earlier allows remote attackers to execute
arbitrary code via a PN-DCP packet with format string specifiers in
the station name.  NOTE: some of these details are obtained from third
party information.

CVE-2009-1268
The Check Point High-Availability Protocol (CPHAP) dissector in
Wireshark 0.9.6 through 1.0.6 allows remote attackers to cause a
denial of service (crash) via a crafted FWHA_MY_STATE packet.

CVE-2009-1269
Unspecified vulnerability in Wireshark 0.99.6 through 1.0.6 allows
remote attackers to cause a denial of service (crash) via a crafted
Tektronix .rf5 file.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2009-02.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34291");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34457");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/defce068-39aa-11de-a493-001b77d09812.html");

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

bver = portver(pkg:"wireshark");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.6")>=0 && revcomp(a:bver, b:"1.0.7")<0) {
  txt += 'Package wireshark version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"wireshark-lite");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.6")>=0 && revcomp(a:bver, b:"1.0.7")<0) {
  txt += 'Package wireshark-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
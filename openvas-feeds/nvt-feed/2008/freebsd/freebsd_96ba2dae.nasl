# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52530");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2003-0989", "CVE-2003-1029", "CVE-2004-0057");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: tcpdump");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: tcpdump

CVE-2003-0989
tcpdump before 3.8.1 allows remote attackers to cause a denial of
service (infinite loop) via certain ISAKMP packets, a different
vulnerability than CVE-2004-0057.

CVE-2003-1029
The L2TP protocol parser in tcpdump 3.8.1 and earlier allows remote
attackers to cause a denial of service (infinite loop and memory
consumption) via a packet with invalid data to UDP port 1701, which
causes l2tp_avp_print to use a bad length value when calling
print_octets.

CVE-2004-0057
The rawprint function in the ISAKMP decoding routines (print-isakmp.c)
for tcpdump 3.8.1 and earlier allows remote attackers to cause a
denial of service (segmentation fault) via malformed ISAKMP packets
that cause invalid 'len' or 'loc' values to be used in a loop, a
different vulnerability than CVE-2003-0989.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.tcpdump.org/lists/workers/2003/12/msg00083.html");
  script_xref(name:"URL", value:"https://marc.info/?l=tcpdump-workers&m=107325073018070&w=2");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/96ba2dae-4ab0-11d8-96f2-0020ed76ef5a.html");

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

bver = portver(pkg:"tcpdump");
if(!isnull(bver) && revcomp(a:bver, b:"3.8.1_351")<0) {
  txt += 'Package tcpdump version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
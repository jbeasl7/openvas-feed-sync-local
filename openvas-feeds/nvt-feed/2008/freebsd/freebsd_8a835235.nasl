# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60052");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2007-6112", "CVE-2007-6113", "CVE-2007-6114", "CVE-2007-6115", "CVE-2007-6117", "CVE-2007-6118", "CVE-2007-6120", "CVE-2007-6121", "CVE-2007-6438", "CVE-2007-6439", "CVE-2007-6441", "CVE-2007-6450", "CVE-2007-6451");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("wireshark -- multiple vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  wireshark
   wireshark-lite
   ethereal
   ethereal-lite
   tethereal
   tethereal-lite

CVE-2007-6438
Unspecified vulnerability in the SMB dissector in Wireshark (formerly
Ethereal) 0.99.6 allows remote attackers to cause a denial of service
via unknown vectors.  NOTE: this identifier originally included MP3
and NCP, but those issues are already covered by CVE-2007-6111.

CVE-2007-6439
Wireshark (formerly Ethereal) 0.99.6 allows remote attackers to cause
a denial of service (infinite or large loop) via the (1) IPv6 or (2)
USB dissector, which can trigger resource consumption or a crash.
NOTE: this identifier originally included Firebird/Interbase, but it
is already covered by CVE-2007-6116.  The DCP ETSI issue is already
covered by CVE-2007-6119.

CVE-2007-6441
The WiMAX dissector in Wireshark (formerly Ethereal) 0.99.6 allows
remote attackers to cause a denial of service (crash) via unknown
vectors related to 'unaligned access on some platforms.'

CVE-2007-6450
The RPL dissector in Wireshark (formerly Ethereal) 0.9.8 to 0.99.6
allows remote attackers to cause a denial of service (infinite loop)
via unknown vectors.

CVE-2007-6451
Unspecified vulnerability in the CIP dissector in Wireshark (formerly
Ethereal) 0.9.14 to 0.99.6 allows remote attackers to cause a denial
of service (crash) via unknown vectors that trigger allocation of
large amounts of memory.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2007-03.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/8a835235-ae84-11dc-a5f9-001a4d49522b.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"0.8.16")>=0 && revcomp(a:bver, b:"0.99.7")<0) {
  txt += 'Package wireshark version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"wireshark-lite");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.16")>=0 && revcomp(a:bver, b:"0.99.7")<0) {
  txt += 'Package wireshark-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ethereal");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.16")>=0 && revcomp(a:bver, b:"0.99.7")<0) {
  txt += 'Package ethereal version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ethereal-lite");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.16")>=0 && revcomp(a:bver, b:"0.99.7")<0) {
  txt += 'Package ethereal-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"tethereal");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.16")>=0 && revcomp(a:bver, b:"0.99.7")<0) {
  txt += 'Package tethereal version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"tethereal-lite");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.16")>=0 && revcomp(a:bver, b:"0.99.7")<0) {
  txt += 'Package tethereal-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52433");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0504", "CVE-2004-0505", "CVE-2004-0506", "CVE-2004-0507");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: ethereal, ethereal-lite, tethereal, tethereal-lite");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:
   ethereal
   ethereal-lite
   tethereal
   tethereal-lite

CVE-2004-0504
Ethereal 0.10.3 allows remote attackers to cause a denial of service
(crash) via certain SIP messages between Hotsip servers and clients.

CVE-2004-0505
The AIM dissector in Ethereal 0.10.3 allows remote attackers to cause
a denial of service (assert error) via unknown attack vectors.

CVE-2004-0506
The SPNEGO dissector in Ethereal 0.9.8 to 0.10.3 allows remote
attackers to cause a denial of service (crash) via unknown attack
vectors that cause a null pointer dereference.

CVE-2004-0507
Buffer overflow in the MMSE dissector for Ethereal 0.10.1 to 0.10.3
allows remote attackers to cause a denial of service and possibly
execute arbitrary code.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
software upgrades.");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.ethereal.com/appnotes/enpa-sa-00014.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10347");
  script_xref(name:"URL", value:"http://secunia.com/advisories/11608");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/74d06b67-d2cf-11d8-b479-02e0185c0b53.html");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

txt = "";
vuln = FALSE;

bver = portver(pkg:"ethereal");
if(!isnull(bver) && revcomp(a:bver, b:"0.10.4")<0) {
  txt += 'Package ethereal version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ethereal-lite");
if(!isnull(bver) && revcomp(a:bver, b:"0.10.4")<0) {
  txt += 'Package ethereal-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"tethereal");
if(!isnull(bver) && revcomp(a:bver, b:"0.10.4")<0) {
  txt += 'Package tethereal version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"tethereal-lite");
if(!isnull(bver) && revcomp(a:bver, b:"0.10.4")<0) {
  txt += 'Package tethereal-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
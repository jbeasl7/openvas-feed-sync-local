# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52195");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-0006", "CVE-2005-0007", "CVE-2005-0008", "CVE-2005-0009", "CVE-2005-0010", "CVE-2005-0084");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
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

CVE-2005-0006
The COPS dissector in Ethereal 0.10.6 through 0.10.8 allows remote
attackers to cause a denial of service (infinite loop).

CVE-2005-0007
Unknown vulnerability in the DLSw dissector in Ethereal 0.10.6 through
0.10.8 allows remote attackers to cause a denial of service
(application crash from assertion).

CVE-2005-0008
Unknown vulnerability in the DNP dissector in Ethereal 0.10.5 through
0.10.8 allows remote attackers to cause 'memory corruption.'

CVE-2005-0009
Unknown vulnerability in the Gnutella dissector in Ethereal 0.10.6
through 0.10.8 allows remote attackers to cause a denial of service
(application crash).

CVE-2005-0010
Unknown vulnerability in the MMSE dissector in Ethereal 0.10.4 through
0.10.8 allows remote attackers to cause a denial of service by
triggering a free of statically allocated memory.

CVE-2005-0084
Buffer overflow in the X11 dissector in Ethereal 0.8.10 through 0.10.8
allows remote attackers to execute arbitrary code via a crafted
packet.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.ethereal.com/appnotes/enpa-sa-00017.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12326");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/831a6a66-79fa-11d9-a9e7-0001020eed82.html");

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

bver = portver(pkg:"ethereal");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.10")>=0 && revcomp(a:bver, b:"0.10.9")<0) {
  txt += 'Package ethereal version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ethereal-lite");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.10")>=0 && revcomp(a:bver, b:"0.10.9")<0) {
  txt += 'Package ethereal-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"tethereal");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.10")>=0 && revcomp(a:bver, b:"0.10.9")<0) {
  txt += 'Package tethereal version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"tethereal-lite");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.10")>=0 && revcomp(a:bver, b:"0.10.9")<0) {
  txt += 'Package tethereal-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
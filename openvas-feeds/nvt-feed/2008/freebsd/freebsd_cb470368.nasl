# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52156");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-0699", "CVE-2005-0704", "CVE-2005-0705", "CVE-2005-0739");
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

CVE-2005-0699
Multiple buffer overflows in the dissect_a11_radius function in the
CDMA A11 (3G-A11) dissector (packet-3g-a11.c) for Ethereal 0.10.9 and
earlier allow remote attackers to execute arbitrary code via RADIUS
authentication packets with large length values.

CVE-2005-0704
Buffer overflow in the Etheric dissector in Ethereal 0.10.7 through
0.10.9 allows remote attackers to cause a denial of service
(application crash) and possibly execute arbitrary code.

CVE-2005-0705
The GPRS-LLC dissector in Ethereal 0.10.7 through 0.10.9, with the
'ignore cipher bit' option enabled. allows remote attackers to cause a
denial of service (application crash).

CVE-2005-0739
The IAPP dissector (packet-iapp.c) for Ethereal 0.9.1 to 0.10.9 does
not properly use certain routines for formatting strings, which could
leave it vulnerable to buffer overflows, as demonstrated using
modified length values that are not properly handled by the
dissect_pdus and pduval_to_str functions.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.ethereal.com/appnotes/enpa-sa-00018.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/cb470368-94d2-11d9-a9e0-0001020eed82.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"0.9.1")>=0 && revcomp(a:bver, b:"0.10.10")<0) {
  txt += 'Package ethereal version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ethereal-lite");
if(!isnull(bver) && revcomp(a:bver, b:"0.9.1")>=0 && revcomp(a:bver, b:"0.10.10")<0) {
  txt += 'Package ethereal-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"tethereal");
if(!isnull(bver) && revcomp(a:bver, b:"0.9.1")>=0 && revcomp(a:bver, b:"0.10.10")<0) {
  txt += 'Package tethereal version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"tethereal-lite");
if(!isnull(bver) && revcomp(a:bver, b:"0.9.1")>=0 && revcomp(a:bver, b:"0.10.10")<0) {
  txt += 'Package tethereal-lite version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}

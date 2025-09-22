# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52455");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0097");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: pwlib");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  pwlib
   asterisk
   openh323

CVE-2004-0097
Multiple vulnerabilities in PWLib before 1.6.0 allow remote attackers
to cause a denial of service and possibly execute arbitrary code, as
demonstrated by the NISCC/OUSPG PROTOS test suite for the H.225
protocol.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.uniras.gov.uk/vuls/2004/006489/h323.htm");
  script_xref(name:"URL", value:"http://www.ee.oulu.fi/research/ouspg/protos/testing/c07/h2250v4/index.html");
  script_xref(name:"URL", value:"http://www.southeren.com/blog/archives/000055.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/27c331d5-64c7-11d8-80e3-0020ed76ef5a.html");

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

bver = portver(pkg:"pwlib");
if(!isnull(bver) && revcomp(a:bver, b:"1.5.0_5")<0) {
  txt += 'Package pwlib version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"asterisk");
if(!isnull(bver) && revcomp(a:bver, b:"0.7.2")<=0) {
  txt += 'Package asterisk version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"openh323");
if(!isnull(bver) && revcomp(a:bver, b:"1.12.0_4")<0) {
  txt += 'Package openh323 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
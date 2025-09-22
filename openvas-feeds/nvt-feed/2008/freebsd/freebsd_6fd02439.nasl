# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52486");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0005", "CVE-2004-0006", "CVE-2004-0007", "CVE-2004-0008");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-16 20:47:22 +0000 (Fri, 16 Feb 2024)");
  script_name("FreeBSD Ports: gaim, ja-gaim, ko-gaim, ru-gaim");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  gaim
   ja-gaim
   ko-gaim
   ru-gaim

The installed versions suffer from numerous buffer
overflows that allow attackers to execute arbitrary
code on the system.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://security.e-matters.de/advisories/012004.txt");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/6fd02439-5d70-11d8-80e3-0020ed76ef5a.html");

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

bver = portver(pkg:"gaim");
if(!isnull(bver) && revcomp(a:bver, b:"0.75_3")<0) {
  txt += 'Package gaim version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"0.75_5")==0) {
  txt += 'Package gaim version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"0.76")==0) {
  txt += 'Package gaim version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ja-gaim");
if(!isnull(bver) && revcomp(a:bver, b:"0.75_3")<0) {
  txt += 'Package ja-gaim version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"0.75_5")==0) {
  txt += 'Package ja-gaim version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"0.76")==0) {
  txt += 'Package ja-gaim version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ko-gaim");
if(!isnull(bver) && revcomp(a:bver, b:"0.75_3")<0) {
  txt += 'Package ko-gaim version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"0.75_5")==0) {
  txt += 'Package ko-gaim version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"0.76")==0) {
  txt += 'Package ko-gaim version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ru-gaim");
if(!isnull(bver) && revcomp(a:bver, b:"0.75_3")<0) {
  txt += 'Package ru-gaim version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"0.75_5")==0) {
  txt += 'Package ru-gaim version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"0.76")==0) {
  txt += 'Package ru-gaim version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"gaim");
if(!isnull(bver) && revcomp(a:bver, b:"20030000")>=0) {
  txt += 'Package gaim version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
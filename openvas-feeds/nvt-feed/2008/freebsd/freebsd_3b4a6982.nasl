# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55043");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-1850", "CVE-2005-1851", "CVE-2005-1852", "CVE-2005-2369", "CVE-2005-2370", "CVE-2005-2448");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: gaim, ja-gaim, ko-gaim, ru-gaim");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  gaim, ja-gaim, ko-gaim, ru-gaim, kdenetwork, pl-ekg, centericq, pl-gnugadu

CVE-2005-1850
Certain contributed scripts for ekg Gadu Gadu client 1.5 and earlier
create temporary files insecurely, with unknown impact and attack
vectors, a different vulnerability than CVE-2005-1916.

CVE-2005-1851
A certain contributed script for ekg Gadu Gadu client 1.5 and earlier
allows attackers to execute shell commands via unknown attack vectors.

CVE-2005-1852
Multiple integer overflows in libgadu, as used in Kopete in KDE 3.2.3
to 3.4.1, ekg before 1.6rc3, and other packages, allows remote
attackers to cause a denial of service (crash) and possibly execute
arbitrary code via an incoming message.

CVE-2005-2369
Multiple integer signedness errors in libgadu, as used in ekg before
1.6rc2 and other packages, may allow remote attackers to cause a
denial of service or execute arbitrary code.

CVE-2005-2370
Multiple 'memory alignment errors' in libgadu, as used in ekg before
1.6rc2 and other packages, allows remote attackers to cause a denial
of service (bus error) on certain architectures such as SPARC via an
incoming message.

CVE-2005-2448
Multiple 'endianness errors' in libgadu in ekg before 1.6rc2 allow
remote attackers to cause a denial of service (invalid behaviour in
applications) on big-endian systems.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://gaim.sourceforge.net/security/?id=20");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14345");
  script_xref(name:"URL", value:"http://www.kde.org/info/security/advisory-20050721-1.txt");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=112198499417250");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/3b4a6982-0b24-11da-bc08-0001020eed82.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"1.5.0")<0) {
  txt += 'Package gaim version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ja-gaim");
if(!isnull(bver) && revcomp(a:bver, b:"1.5.0")<0) {
  txt += 'Package ja-gaim version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ko-gaim");
if(!isnull(bver) && revcomp(a:bver, b:"1.5.0")<0) {
  txt += 'Package ko-gaim version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ru-gaim");
if(!isnull(bver) && revcomp(a:bver, b:"1.5.0")<0) {
  txt += 'Package ru-gaim version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"kdenetwork");
if(!isnull(bver) && revcomp(a:bver, b:"3.2.2")>0 && revcomp(a:bver, b:"3.4.2")<0) {
  txt += 'Package kdenetwork version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"pl-ekg");
if(!isnull(bver) && revcomp(a:bver, b:"1.6r3,1")<0) {
  txt += 'Package pl-ekg version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"centericq");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package centericq version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"pl-gnugadu");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package pl-gnugadu version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
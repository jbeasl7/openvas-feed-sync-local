# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52395");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0752");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_name("openoffice -- document disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  openoffice, ar-openoffice, ca-openoffice, cs-openoffice, de-openoffice, dk-openoffice
  el-openoffice, es-openoffice, et-openoffice, fi-openoffice, fr-openoffice, gr-openoffice,
  hu-openoffice, it-openoffice, ja-openoffice, ko-openoffice, nl-openoffice, pl-openoffice,
  pt-openoffice, pt_BR-openoffice, ru-openoffice, se-openoffice, sk-openoffice, sl-openoffice-SI,
  tr-openoffice, zh-openoffice-CN, zh-openoffice-TW

CVE-2004-0752
OpenOffice (OOo) 1.1.2 creates predictable directory names with
insecure permissions during startup, which may allow local users to
read or list files of other users.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.openoffice.org/issues/show_bug.cgi?id=33357");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11151");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2004/Sep/1011205.html");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=109483308421566");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/c62dc69f-05c8-11d9-b45d-000c41e2cdad.html");

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

bver = portver(pkg:"openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ar-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package ar-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package ar-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ca-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package ca-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package ca-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"cs-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package cs-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package cs-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"de-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package de-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package de-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"dk-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package dk-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package dk-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"el-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package el-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package el-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"es-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package es-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package es-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"et-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package et-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package et-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"fi-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package fi-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package fi-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"fr-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package fr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package fr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"gr-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package gr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package gr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"hu-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package hu-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package hu-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"it-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package it-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package it-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ja-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package ja-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package ja-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ko-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package ko-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package ko-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"nl-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package nl-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package nl-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"pl-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package pl-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package pl-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"pt-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package pt-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package pt-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"pt_BR-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package pt_BR-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package pt_BR-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ru-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package ru-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package ru-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"se-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package se-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package se-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"sk-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package sk-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package sk-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"sl-openoffice-SI");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package sl-openoffice-SI version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package sl-openoffice-SI version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"tr-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package tr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package tr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"zh-openoffice-CN");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package zh-openoffice-CN version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package zh-openoffice-CN version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"zh-openoffice-TW");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2_1")<0) {
  txt += 'Package zh-openoffice-TW version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0) {
  txt += 'Package zh-openoffice-TW version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
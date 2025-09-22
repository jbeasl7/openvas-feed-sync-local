# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52138");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-0941");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("openoffice -- DOC document heap overflow vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  openoffice, ar-openoffice, ca-openoffice, cs-openoffice, de-openoffice,
  dk-openoffice, el-openoffice, es-openoffice, et-openoffice, fi-openoffice,
  fr-openoffice, gr-openoffice, hu-openoffice, it-openoffice, ja-openoffice,
  ko-openoffice, nl-openoffice, pl-openoffice, pt-openoffice, pt_BR-openoffice,
  ru-openoffice, se-openoffice, sk-openoffice, sl-openoffice-SI, tr-openoffice,
  zh-openoffice-CN, zh-openoffice-TW, jp-openoffice, kr-openoffice, sl-openoffice-SL,
  zh-openoffice, zh_TW-openoffice

CVE-2005-0941
The StgCompObjStream::Load function in OpenOffice.org OpenOffice 1.1.4
and earlier allocates memory based on 16 bit length values, but
process memory using 32 bit values, which allows remote attackers to
cause a denial of service and possibly execute arbitrary code via a
DOC document with certain length values, which leads to a heap-based
buffer overflow.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.openoffice.org/issues/show_bug.cgi?id=46388");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13092");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=111325305109137");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/b206dd82-ac67-11d9-a788-0001020eed82.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ar-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package ar-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package ar-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ca-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package ca-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package ca-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"cs-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package cs-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package cs-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"de-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package de-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package de-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"dk-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package dk-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package dk-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"el-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package el-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package el-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"es-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package es-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package es-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"et-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package et-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package et-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"fi-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package fi-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package fi-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"fr-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package fr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package fr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"gr-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package gr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package gr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"hu-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package hu-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package hu-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"it-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package it-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package it-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ja-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package ja-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package ja-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ko-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package ko-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package ko-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"nl-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package nl-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package nl-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"pl-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package pl-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package pl-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"pt-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package pt-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package pt-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"pt_BR-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package pt_BR-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package pt_BR-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ru-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package ru-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package ru-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"se-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package se-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package se-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"sk-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package sk-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package sk-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"sl-openoffice-SI");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package sl-openoffice-SI version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package sl-openoffice-SI version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"tr-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package tr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package tr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"zh-openoffice-CN");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package zh-openoffice-CN version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package zh-openoffice-CN version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"zh-openoffice-TW");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package zh-openoffice-TW version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package zh-openoffice-TW version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"jp-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package jp-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package jp-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"kr-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package kr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package kr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"sl-openoffice-SL");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package sl-openoffice-SL version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package sl-openoffice-SL version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"zh-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package zh-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package zh-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"zh_TW-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
  txt += 'Package zh_TW-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
  txt += 'Package zh_TW-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"6.0.a609")>=0 && revcomp(a:bver, b:"6.0.a638")<=0) {
  txt += 'Package openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"641c")>=0 && revcomp(a:bver, b:"645")<=0) {
  txt += 'Package openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.1RC4")==0) {
  txt += 'Package openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.1rc5")==0) {
  txt += 'Package openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ja-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"6.0.a609")>=0 && revcomp(a:bver, b:"6.0.a638")<=0) {
  txt += 'Package ja-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"641c")>=0 && revcomp(a:bver, b:"645")<=0) {
  txt += 'Package ja-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.1RC4")==0) {
  txt += 'Package ja-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.1rc5")==0) {
  txt += 'Package ja-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56576");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-0749", "CVE-2006-1045", "CVE-2006-1529", "CVE-2006-1530", "CVE-2006-1531", "CVE-2006-1723", "CVE-2006-1724", "CVE-2006-1725", "CVE-2006-1726", "CVE-2006-1727", "CVE-2006-1728", "CVE-2006-1729", "CVE-2006-1730", "CVE-2006-1731", "CVE-2006-1732", "CVE-2006-1733", "CVE-2006-1734", "CVE-2006-1735", "CVE-2006-1736", "CVE-2006-1737", "CVE-2006-1738", "CVE-2006-1739", "CVE-2006-1740", "CVE-2006-1741", "CVE-2006-1742", "CVE-2006-1790");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  firefox
   linux-firefox
   mozilla
   linux-mozilla
   linux-mozilla-devel
   seamonkey
   thunderbird
   mozilla-thunderbird

For details, please visit the referenced security advisories.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-09.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-10.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-11.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-12.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-13.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-14.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-15.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-16.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-17.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-18.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-19.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-20.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-22.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-23.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-25.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-26.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-28.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-29.html");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-06-010.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/84630f4a-cd8c-11da-b7b9-000c6ec775d9.html");

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

bver = portver(pkg:"firefox");
if(!isnull(bver) && revcomp(a:bver, b:"1.0.8,1")<0) {
  txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.5.*,1")>0 && revcomp(a:bver, b:"1.5.0.2,1")<0) {
  txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-firefox");
if(!isnull(bver) && revcomp(a:bver, b:"1.5.0.2")<0) {
  txt += 'Package linux-firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mozilla");
if(!isnull(bver) && revcomp(a:bver, b:"1.7.13,2")<0) {
  txt += 'Package mozilla version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.8.*,2")>=0) {
  txt += 'Package mozilla version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-mozilla");
if(!isnull(bver) && revcomp(a:bver, b:"1.7.13")<0) {
  txt += 'Package linux-mozilla version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-mozilla-devel");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package linux-mozilla-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"1.0.1")<0) {
  txt += 'Package seamonkey version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"1.5.0.2")<0) {
  txt += 'Package thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mozilla-thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"1.5.0.2")<0) {
  txt += 'Package mozilla-thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
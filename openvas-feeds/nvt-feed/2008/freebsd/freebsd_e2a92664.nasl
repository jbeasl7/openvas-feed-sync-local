# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57146");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-3113", "CVE-2006-3677", "CVE-2006-3801", "CVE-2006-3802", "CVE-2006-3803", "CVE-2006-3804", "CVE-2006-3805", "CVE-2006-3806", "CVE-2006-3807", "CVE-2006-3808", "CVE-2006-3809", "CVE-2006-3810", "CVE-2006-3811", "CVE-2006-3812");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  firefox
   linux-firefox
   linux-firefox-devel
   seamonkey
   linux-seamonkey
   thunderbird
   linux-thunderbird
   mozilla-thunderbird
   mozilla
   linux-mozilla
   linux-mozilla-devel");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html#seamonkey1.0.3");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-44.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-45.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-46.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-47.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-48.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-49.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-50.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-51.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-52.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-53.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-54.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-55.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-56.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/e2a92664-1d60-11db-88cf-000c6ec775d9.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"1.5.0.5,1")<0) {
  txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.*,1")>0) {
  txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-firefox");
if(!isnull(bver) && revcomp(a:bver, b:"1.5.0.5")<0) {
  txt += 'Package linux-firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-firefox-devel");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.a2006.07.26")<0) {
  txt += 'Package linux-firefox-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"1.0.3")<0) {
  txt += 'Package seamonkey version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"1.0.3")<0) {
  txt += 'Package linux-seamonkey version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"1.5.0.5")<0) {
  txt += 'Package thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"1.5.0.5")<0) {
  txt += 'Package linux-thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mozilla-thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"1.5.0.5")<0) {
  txt += 'Package mozilla-thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"mozilla");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package mozilla version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-mozilla");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package linux-mozilla version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-mozilla-devel");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package linux-mozilla-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
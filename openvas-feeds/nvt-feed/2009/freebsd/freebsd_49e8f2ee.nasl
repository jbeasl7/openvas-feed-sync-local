# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64577");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
  script_cve_id("CVE-2009-2404", "CVE-2009-2408", "CVE-2009-2454", "CVE-2009-2470");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-14 17:21:52 +0000 (Wed, 14 Feb 2024)");
  script_name("FreeBSD Ports: firefox, linux-firefox-devel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  firefox linux-firefox-devel firefox3
   linux-firefox firefox35 thunderbird
   linux-thunderbird seamonkey linux-seamonkey

CVE-2009-2404
Heap-based buffer overflow in a regular-expression parser in Mozilla
Network Security Services (NSS) before 3.12.3, as used in Firefox,
Thunderbird, SeaMonkey, Evolution, Pidgin, and AOL Instant Messenger
(AIM), allows remote SSL servers to cause a denial of service
(application crash) or possibly execute arbitrary code via a long
domain name in the subject's Common Name (CN) field of an X.509
certificate, related to the cert_TestHostName function.

CVE-2009-2408
Mozilla Firefox before 3.5 and NSS before 3.12.3 do not properly
handle a '\0' character in a domain name in the subject's Common Name
(CN) field of an X.509 certificate, which allows man-in-the-middle
attackers to spoof arbitrary SSL servers via a crafted certificate
issued by a legitimate Certification Authority.

CVE-2009-2454
Cross-site scripting (XSS) vulnerability in Citrix Web Interface 4.6,
5.0, and 5.0.1 allows remote attackers to inject arbitrary web script
or HTML via unspecified vectors.

CVE-2009-2470
Mozilla Firefox before 3.0.12, and 3.5.x before 3.5.2, allows remote
SOCKS5 proxy servers to cause a denial of service (data stream
corruption) via a long domain name in a reply.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-38.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-42.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-43.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-44.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-45.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-46.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/49e8f2ee-8147-11de-a994-0030843d3802.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-firefox-devel");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package linux-firefox-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"firefox3");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.13")<0) {
  txt += 'Package firefox3 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-firefox");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.13")<0) {
  txt += 'Package linux-firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"firefox35");
if(!isnull(bver) && revcomp(a:bver, b:"3.5.2")<0) {
  txt += 'Package firefox35 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"2.0.0.23")<0) {
  txt += 'Package thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"2.0.0.23")<0) {
  txt += 'Package linux-thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.18")<0) {
  txt += 'Package seamonkey version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.18")<0) {
  txt += 'Package linux-seamonkey version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
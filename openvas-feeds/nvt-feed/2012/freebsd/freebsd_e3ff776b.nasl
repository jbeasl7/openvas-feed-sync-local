# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70588");
  script_tag(name:"creation_date", value:"2012-02-13 01:48:16 +0100 (Mon, 13 Feb 2012)");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-3658", "CVE-2011-3660", "CVE-2011-3661", "CVE-2011-3663", "CVE-2011-3665");
  script_version("2023-07-26T05:05:09+0000");
  script_name("FreeBSD Ports: firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  firefox
   linux-firefox
   linux-seamonkey
   linux-thunderbird
   seamonkey
   thunderbird

CVE-2011-3658
The SVG implementation in Mozilla Firefox 8.0, Thunderbird 8.0, and
SeaMonkey 2.5 does not properly interact with DOMAttrModified event
handlers, which allows remote attackers to cause a denial of service
(out-of-bounds memory access) or possibly have unspecified other
impact via vectors involving removal of SVG elements.

CVE-2011-3660
Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox 4.x through 8.0, Thunderbird 5.0 through 8.0, and SeaMonkey
before 2.6 allow remote attackers to cause a denial of service (memory
corruption and application crash) or possibly execute arbitrary code
via vectors that trigger a compartment mismatch associated with the
nsDOMMessageEvent::GetData function, and unknown other vectors.

CVE-2011-3661
YARR, as used in Mozilla Firefox 4.x through 8.0, Thunderbird 5.0
through 8.0, and SeaMonkey before 2.6, allows remote attackers to
cause a denial of service (application crash) or possibly execute
arbitrary code via crafted JavaScript.

CVE-2011-3663
Mozilla Firefox 4.x through 8.0, Thunderbird 5.0 through 8.0, and
SeaMonkey before 2.6 allow remote attackers to capture keystrokes
entered on a web page, even when JavaScript is disabled, by using SVG
animation accessKey events within that web page.

CVE-2011-3665
Mozilla Firefox 4.x through 8.0, Thunderbird 5.0 through 8.0, and
SeaMonkey before 2.6 allow remote attackers to cause a denial of
service (application crash) or possibly have unspecified other impact
via an Ogg VIDEO element that is not properly handled after scaling.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-53.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-54.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-55.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-56.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-58.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/e3ff776b-2ba6-11e1-93c6-0011856a6e37.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"4.0,1")>0 && revcomp(a:bver, b:"9.0,1")<0) {
  txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-firefox");
if(!isnull(bver) && revcomp(a:bver, b:"9.0,1")<0) {
  txt += 'Package linux-firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.6")<0) {
  txt += 'Package linux-seamonkey version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"9.0")<0) {
  txt += 'Package linux-thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.6")<0) {
  txt += 'Package seamonkey version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"4.0")>0 && revcomp(a:bver, b:"9.0")<0) {
  txt += 'Package thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
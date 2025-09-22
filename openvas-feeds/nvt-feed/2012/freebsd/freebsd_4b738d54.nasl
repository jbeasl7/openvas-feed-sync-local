# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72616");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2012-4730", "CVE-2012-4731", "CVE-2012-4732", "CVE-2012-4734", "CVE-2012-4735", "CVE-2012-4884");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-11-26 12:47:33 -0500 (Mon, 26 Nov 2012)");
  script_name("FreeBSD Ports: rt40");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  rt40
   rt38

CVE-2012-4730
Request Tracker (RT) 3.8.x before 3.8.15 and 4.0.x before 4.0.8 allows
remote authenticated users with ModifySelf or AdminUser privileges to
inject arbitrary email headers and conduct phishing attacks or obtain
sensitive information via unknown vectors.
CVE-2012-4731
FAQ manager for Request Tracker (RTFM) before 2.4.5 does not properly
check user rights, which allows remote authenticated users to create
arbitrary articles in arbitrary classes via unknown vectors.
CVE-2012-4732
Cross-site request forgery (CSRF) vulnerability in Request Tracker
(RT) 3.8.12 and other versions before 3.8.15, and 4.0.6 and other
versions before 4.0.8, allows remote attackers to hijack the
authentication of users for requests that toggle ticket bookmarks.
CVE-2012-4734
Request Tracker (RT) 3.8.x before 3.8.15 and 4.0.x before 4.0.8 allows
remote attackers to conduct a 'confused deputy' attack to bypass the
CSRF warning protection mechanism and cause victims to 'modify
arbitrary state' via unknown vectors related to a crafted link.
CVE-2012-4884
Argument injection vulnerability in Request Tracker (RT) 3.8.x before
3.8.15 and 4.0.x before 4.0.8 allows remote attackers to create
arbitrary files via unspecified vectors related to the GnuPG client.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://blog.bestpractical.com/2012/10/security-vulnerabilities-in-rt.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/4b738d54-2427-11e2-9817-c8600054b392.html");

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

bver = portver(pkg:"rt40");
if(!isnull(bver) && revcomp(a:bver, b:"4.0")>=0 && revcomp(a:bver, b:"4.0.8")<0) {
  txt += "Package rt40 version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"rt38");
if(!isnull(bver) && revcomp(a:bver, b:"3.8.15")<0) {
  txt += "Package rt38 version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
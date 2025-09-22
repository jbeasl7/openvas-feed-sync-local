# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71272");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2012-2399", "CVE-2012-2400", "CVE-2012-2401", "CVE-2012-2402", "CVE-2012-2403", "CVE-2012-2404");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-04-30 07:59:26 -0400 (Mon, 30 Apr 2012)");
  script_name("FreeBSD Ports: wordpress");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: wordpress

CVE-2012-2399
Unspecified vulnerability in wp-includes/js/swfupload/swfupload.swf in
WordPress before 3.3.2 has unknown impact and attack vectors.
CVE-2012-2400
Unspecified vulnerability in wp-includes/js/swfobject.js in WordPress
before 3.3.2 has unknown impact and attack vectors.
CVE-2012-2401
Plupload before 1.5.4, as used in wp-includes/js/plupload/ in
WordPress before 3.3.2 and other products, enables scripting
regardless of the domain from which the SWF content was loaded, which
allows remote attackers to bypass the Same Origin Policy via crafted
content.
CVE-2012-2402
wp-admin/plugins.php in WordPress before 3.3.2 allows remote
authenticated site administrators to bypass intended access
restrictions and deactivate network-wide plugins via unspecified
vectors.
CVE-2012-2403
wp-includes/formatting.php in WordPress before 3.3.2 attempts to
enable clickable links inside attributes, which makes it easier for
remote attackers to conduct cross-site scripting (XSS) attacks via
unspecified vectors.
CVE-2012-2404
wp-comments-post.php in WordPress before 3.3.2 supports offsite
redirects, which makes it easier for remote attackers to conduct
cross-site scripting (XSS) attacks via unspecified vectors.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://codex.wordpress.org/Version_3.3.2");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/b384cc5b-8d56-11e1-8d7b-003067b2972c.html");

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

bver = portver(pkg:"wordpress");
if(!isnull(bver) && revcomp(a:bver, b:"3.3.2,1")<0) {
  txt += "Package wordpress version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
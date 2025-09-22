# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53079");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-1106", "CVE-2005-0219", "CVE-2005-0220", "CVE-2005-0221", "CVE-2005-0222");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: gallery");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: gallery

CVE-2004-1106
Cross-site scripting (XSS) vulnerability in Gallery 1.4.4-pl3 and
earlier allows remote attackers to execute arbitrary web script or
HTML via 'specially formed URLs, ' possibly via the include parameter
in index.php.

CVE-2005-0219
Multiple cross-site scripting (XSS) vulnerabilities in Gallery
1.3.4-pl1 allow remote attackers to inject arbitrary web script or
HTML via (1) the index field in add_comment.php, (2) set_albumName,
(3) slide_index, (4) slide_full, (5) slide_loop, (6) slide_pause, (7)
slide_dir fields in slideshow_low.php, or (8) username field in
search.php.

CVE-2005-0220
Cross-site scripting vulnerability in login.php in Gallery 1.4.4-pl2
allows remote attackers to inject arbitrary web script or HTML via the
username field.

CVE-2005-0221
Cross-site scripting (XSS) vulnerability in login.php in Gallery 2.0
Alpha allows remote attackers to inject arbitrary web script or HTML
via the g2_form[subject] field.

CVE-2005-0222
main.php in Gallery 2.0 Alpha allows remote attackers to gain
sensitive information by changing the value of g2_subView parameter,
which reveals the path in an error message.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://gallery.menalto.com/modules.php?op=modload&name=News&file=article&sid=147");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11602");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=110608459222364");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/5752a0df-60c5-4876-a872-f12f9a02fa05.html");

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

bver = portver(pkg:"gallery");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.4.5")<0) {
  txt += 'Package gallery version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
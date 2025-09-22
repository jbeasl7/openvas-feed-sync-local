# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67358");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-05-04 05:52:15 +0200 (Tue, 04 May 2010)");
  script_cve_id("CVE-2010-0996", "CVE-2010-0997");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_name("FreeBSD Ports: e107");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: e107

CVE-2010-0996
Unrestricted file upload vulnerability in e107 before 0.7.20 allows
remote authenticated users to execute arbitrary code by uploading a
.php.filetypesphp file.  NOTE: the vendor disputes the significance of
this issue, noting that 'an odd set of preferences and a missing file'
are required.

CVE-2010-0997
Cross-site scripting (XSS) vulnerability in
107_plugins/content/content_manager.php in the Content Management
plugin in e107 before 0.7.20, when the personal content manager is
enabled, allows user-assisted remote authenticated users to inject
arbitrary web script or HTML via the content_heading parameter.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://e107.org/comment.php?comment.news.864");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39540");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2010-43/");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2010-44/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57932");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/a4746a86-4c89-11df-83fb-0015587e2cc1.html");

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

bver = portver(pkg:"e107");
if(!isnull(bver) && revcomp(a:bver, b:"0.7.20")<0) {
  txt += 'Package e107 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
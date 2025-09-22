# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60885");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2008-1385", "CVE-2008-1386");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("FreeBSD Ports: serendipity");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  serendipity
   serendipity-devel

CVE-2008-1385
Cross-site scripting (XSS) vulnerability in the Top Referrers (aka
referrer) plugin in Serendipity (S9Y) before 1.3.1 allows remote
attackers to inject arbitrary web script or HTML via the Referer HTTP
header.
CVE-2008-1386
Multiple cross-site scripting (XSS) vulnerabilities in the installer
in Serendipity (S9Y) 1.3 allow remote attackers to inject arbitrary
web script or HTML via (1) unspecified path fields or (2) the database
host field.  NOTE: the timing window for exploitation of this issue
might be limited.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://int21.de/cve/CVE-2008-1385-s9y.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/28885");
  script_xref(name:"URL", value:"http://int21.de/cve/CVE-2008-1386-s9y.html");
  script_xref(name:"URL", value:"http://blog.s9y.org/archives/193-Serendipity-1.3.1-released.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/9c133aa0-12bd-11dd-bab7-0016179b2dd5.html");

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

bver = portver(pkg:"serendipity");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.1")<0) {
  txt += 'Package serendipity version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"serendipity-devel");
if(!isnull(bver) && revcomp(a:bver, b:"200804242342")<0) {
  txt += 'Package serendipity-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
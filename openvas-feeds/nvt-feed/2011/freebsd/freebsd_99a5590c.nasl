# SPDX-FileCopyrightText: 2011 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69762");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2011-1928", "CVE-2011-0419");
  script_name("FreeBSD Ports: apr1");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: apr1

CVE-2011-1928
The fnmatch implementation in apr_fnmatch.c in the Apache Portable
Runtime (APR) library 1.4.3 and 1.4.4, and the Apache HTTP Server
2.2.18, allows remote attackers to cause a denial of service (infinite
loop) via a URI that does not match unspecified types of wildcard
patterns, as demonstrated by attacks against mod_autoindex in httpd
when a /*/WEB-INF/ configuration pattern is used.  NOTE: this issue
exists because of an incorrect fix for CVE-2011-0419.

CVE-2011-0419
Stack consumption vulnerability in the fnmatch implementation in
apr_fnmatch.c in the Apache Portable Runtime (APR) library before
1.4.3 and the Apache HTTP Server before 2.2.18, and in fnmatch.c in
libc in NetBSD 5.1, OpenBSD 4.8, FreeBSD, Apple Mac OS X 10.6, Oracle
Solaris 10, and Android, allows context-dependent attackers to cause a
denial of service (CPU and memory consumption) via *? sequences in the
first argument, as demonstrated by attacks against mod_autoindex in
httpd.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.apache.org/dist/apr/Announcement1.x.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47929");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2011-1928");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/99a5590c-857e-11e0-96b7-00300582f9fc.html");

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

bver = portver(pkg:"apr1");
if(!isnull(bver) && revcomp(a:bver, b:"1.4.5.1.3.12")<0) {
  txt += 'Package apr1 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
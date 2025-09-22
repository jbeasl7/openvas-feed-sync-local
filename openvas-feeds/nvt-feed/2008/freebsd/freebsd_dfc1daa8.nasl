# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55939");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-3750");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: linux-opera, opera-devel, opera");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  linux-opera
   opera-devel
   opera

CVE-2005-3750
Opera before 8.51 on Linux and Unix systems allows remote attackers to
execute arbitrary code via shell metacharacters (backticks) in a URL
that another product provides in a command line argument when
launching Opera.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2005-57/advisory/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15521");
  script_xref(name:"URL", value:"http://www.opera.com/support/search/supsearch.dml?index=818");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/dfc1daa8-61de-11da-b64c-0001020eed82.html");

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

bver = portver(pkg:"linux-opera");
if(!isnull(bver) && revcomp(a:bver, b:"8.51")<0) {
  txt += 'Package linux-opera version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"opera-devel");
if(!isnull(bver) && revcomp(a:bver, b:"8.51")<0) {
  txt += 'Package opera-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"opera");
if(!isnull(bver) && revcomp(a:bver, b:"8.51")<0) {
  txt += 'Package opera version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
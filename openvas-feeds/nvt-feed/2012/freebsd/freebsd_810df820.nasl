# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70582");
  script_tag(name:"creation_date", value:"2012-02-13 01:48:16 +0100 (Mon, 13 Feb 2012)");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_name("FreeBSD Ports: wordpress");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  wordpress
   de-wordpress
   zh-wordpress-zh_CN
   zh-wordpress-zh_TW");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://threatpost.com/en_us/blogs/xss-bug-found-wordpress-33-010312");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/810df820-3664-11e1-8fe3-00215c6a37bb.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"3.3.1")<0) {
  txt += 'Package wordpress version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"de-wordpress");
if(!isnull(bver) && revcomp(a:bver, b:"3.3.1")<0) {
  txt += 'Package de-wordpress version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"zh-wordpress-zh_CN");
if(!isnull(bver) && revcomp(a:bver, b:"3.3.1")<0) {
  txt += 'Package zh-wordpress-zh_CN version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"zh-wordpress-zh_TW");
if(!isnull(bver) && revcomp(a:bver, b:"3.3.1")<0) {
  txt += 'Package zh-wordpress-zh_TW version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
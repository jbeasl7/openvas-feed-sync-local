# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52525");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2003-0720", "CVE-2003-0721");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: pine, zh-pine, iw-pine");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  pine
   zh-pine
   iw-pine

CVE-2003-0720
Buffer overflow in PINE before 4.58 allows remote attackers to execute
arbitrary code via a malformed message/external-body MIME type.

CVE-2003-0721
Integer signedness error in rfc2231_get_param from strings.c in PINE
before 4.58 allows remote attackers to execute arbitrary code via an
email that causes an out-of-bounds array access using a negative
number.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.idefense.com/application/poi/display?id=5");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/39bd57e6-5d83-11d8-80e3-0020ed76ef5a.html");

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

bver = portver(pkg:"pine");
if(!isnull(bver) && revcomp(a:bver, b:"4.58")<0) {
  txt += 'Package pine version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"zh-pine");
if(!isnull(bver) && revcomp(a:bver, b:"4.58")<0) {
  txt += 'Package zh-pine version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"iw-pine");
if(!isnull(bver) && revcomp(a:bver, b:"4.58")<0) {
  txt += 'Package iw-pine version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
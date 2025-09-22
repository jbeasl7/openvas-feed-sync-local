# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67287");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-04-21 03:31:17 +0200 (Wed, 21 Apr 2010)");
  script_cve_id("CVE-2010-0734");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: curl");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: curl

CVE-2010-0734
content_encoding.c in libcurl 7.10.5 through 7.19.7, when zlib is
enabled, does not properly restrict the amount of callback data sent
to an application that requests automatic decompression, which might
allow remote attackers to cause a denial of service (application
crash) or have unspecified other impact by sending crafted compressed
data to an application that relies on the intended data-length limit.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://curl.haxx.se/docs/adv_20100209.html");
  script_xref(name:"URL", value:"http://www.debian.org/security/2010/dsa-2023");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/02/09/5");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/c8c31c41-49ed-11df-83fb-0015587e2cc1.html");

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

bver = portver(pkg:"curl");
if(!isnull(bver) && revcomp(a:bver, b:"7.10.5")>=0 && revcomp(a:bver, b:"7.20.0")<0) {
  txt += 'Package curl version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
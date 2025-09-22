# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52518");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2002-0177", "CVE-2001-1230", "CVE-2001-1229", "CVE-2001-1083", "CVE-2001-0784");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2933");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4415");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: icecast");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_xref(name:"URL", value:"https://www.vuxml.org/freebsd/5e92e8a2-5d7b-11d8-80e3-0020ed76ef5a.html");
  script_tag(name:"insight", value:"The following package is affected: icecast

CVE-2002-0177
Buffer overflows in icecast 1.3.11 and earlier allows remote attackers
to execute arbitrary code via a long HTTP GET request from an MP3
client.

CVE-2001-1230
Buffer overflows in Icecast before 1.3.10 allow remote attackers to
cause a denial of service (crash) and execute arbitrary code.

CVE-2001-1229
Buffer overflows in (1) Icecast before 1.3.9 and (2) libshout before
1.0.4 allow remote attackers to cause a denial of service (crash) and
execute arbitrary code.

CVE-2001-1083
Icecast 1.3.7, and other versions before 1.3.11 with HTTP server file
streaming support enabled allows remote attackers to cause a denial of
service (crash) via a URL that ends in . (dot), / (forward slash), or
\ (backward slash).
CVE-2001-0784
Directory traversal vulnerability in Icecast 1.3.10 and earlier allows
remote attackers to read arbitrary files via a modified .. (dot dot)
attack using encoded URL characters.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

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

bver = portver(pkg:"icecast");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.12")<0) {
  txt += 'Package icecast version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}

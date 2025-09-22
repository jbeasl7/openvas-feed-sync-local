# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57675");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-4197");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: libmusicbrainz");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: libmusicbrainz

CVE-2006-4197
Multiple buffer overflows in libmusicbrainz (aka mb_client or
MusicBrainz Client Library) 2.1.2 and earlier, and SVN 8406 and
earlier, allow remote attackers to cause a denial of service (crash)
or execute arbitrary code via (1) a long Location header by the HTTP
server, which triggers an overflow in the MBHttp::Download function in
lib/http.cpp, and (2) a long URL in RDF data, as demonstrated by a URL
in an rdf:resource field in an RDF XML document, which triggers
overflows in many functions in lib/rdfparse.c.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/21185");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/19508");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/ed124f8c-82a2-11db-b46b-0012f06707f0.html");

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

bver = portver(pkg:"libmusicbrainz");
if(!isnull(bver) && revcomp(a:bver, b:"2.1.3")<0) {
  txt += 'Package libmusicbrainz version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
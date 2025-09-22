# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72632");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2012-5130", "CVE-2012-5132", "CVE-2012-5133", "CVE-2012-5134", "CVE-2012-5135", "CVE-2012-5136");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-12-04 11:43:52 -0500 (Tue, 04 Dec 2012)");
  script_name("FreeBSD Ports: chromium");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");

  script_tag(name:"insight", value:"The following package is affected: chromium

CVE-2012-5130
Skia, as used in Google Chrome before 23.0.1271.91, allows remote
attackers to cause a denial of service (out-of-bounds read) via
unspecified vectors.
CVE-2012-5132
Google Chrome before 23.0.1271.91 allows remote attackers to cause a
denial of service (application crash) via a response with chunked
transfer coding.
CVE-2012-5133
Use-after-free vulnerability in Google Chrome before 23.0.1271.91
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to SVG filters.
CVE-2012-5134
Heap-based buffer underflow in the xmlParseAttValueComplex function in
parser.c in libxml2 2.9.0 and earlier, as used in Google Chrome before
23.0.1271.91, allows remote attackers to cause a denial of service or
possibly execute arbitrary code via crafted entities in an XML
document.
CVE-2012-5135
Use-after-free vulnerability in Google Chrome before 23.0.1271.91
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to printing.
CVE-2012-5136
Google Chrome before 23.0.1271.91 does not properly perform a cast of
an unspecified variable during handling of the INPUT element, which
allows remote attackers to cause a denial of service or possibly have
unknown other impact via a crafted HTML document.

This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.nl/search/label/Stable%20updates");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/4d64fc61-3878-11e2-a4eb-00262d5ed8ee.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

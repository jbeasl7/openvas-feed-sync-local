# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72609");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2012-5127", "CVE-2012-5120", "CVE-2012-5116", "CVE-2012-5118", "CVE-2012-5121", "CVE-2012-5117", "CVE-2012-5119", "CVE-2012-5122", "CVE-2012-5123", "CVE-2012-5124", "CVE-2012-5125", "CVE-2012-5126", "CVE-2012-5128");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-11-26 12:47:33 -0500 (Mon, 26 Nov 2012)");
  script_name("FreeBSD Ports: chromium");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");

  script_tag(name:"insight", value:"The following package is affected: chromium

CVE-2012-5127
Integer overflow in Google Chrome before 23.0.1271.64 allows remote
attackers to cause a denial of service (out-of-bounds read) or
possibly have unspecified other impact via a crafted WebP image.
CVE-2012-5120
Google V8 before 3.13.7.5, as used in Google Chrome before
23.0.1271.64, on 64-bit Linux platforms allows remote attackers to
cause a denial of service or possibly have unspecified other impact
via crafted JavaScript code that triggers an out-of-bounds access to
an array.
CVE-2012-5116
Use-after-free vulnerability in Google Chrome before 23.0.1271.64
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to the handling of SVG
filters.
CVE-2012-5118
Google Chrome before 23.0.1271.64 on Mac OS X does not properly
validate an integer value during the handling of GPU command buffers,
which allows remote attackers to cause a denial of service or possibly
have unspecified other impact via unknown vectors.
CVE-2012-5121
Use-after-free vulnerability in Google Chrome before 23.0.1271.64
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to video layout.
CVE-2012-5117
Google Chrome before 23.0.1271.64 does not properly restrict the
loading of an SVG subresource in the context of an IMG element, which
has unspecified impact and remote attack vectors.
CVE-2012-5119
Race condition in Pepper, as used in Google Chrome before
23.0.1271.64, allows remote attackers to cause a denial of service or
possibly have unspecified other impact via vectors related to buffers.

Text truncated. Please see the references for more information.

This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.nl/search/label/Stable%20updates");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/209c068d-28be-11e2-9160-00262d5ed8ee.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

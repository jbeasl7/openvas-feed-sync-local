# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71171");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-3015", "CVE-2011-3016", "CVE-2011-3017", "CVE-2011-3018", "CVE-2011-3019", "CVE-2011-3020", "CVE-2011-3021", "CVE-2011-3022", "CVE-2011-3023", "CVE-2011-3024", "CVE-2011-3025", "CVE-2011-3026", "CVE-2011-3027");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-03-12 11:35:07 -0400 (Mon, 12 Mar 2012)");
  script_name("FreeBSD Ports: chromium");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");

  script_tag(name:"insight", value:"The following package is affected: chromium

CVE-2011-3015
Multiple integer overflows in the PDF codecs in Google Chrome before
17.0.963.56 allow remote attackers to cause a denial of service or
possibly have unspecified other impact via unknown vectors.

CVE-2011-3016
Use-after-free vulnerability in Google Chrome before 17.0.963.56
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors involving counter nodes, related
to a 'read-after-free' issue.

CVE-2011-3017
Use-after-free vulnerability in Google Chrome before 17.0.963.56
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to database handling.

CVE-2011-3018
Heap-based buffer overflow in Google Chrome before 17.0.963.56 allows
remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to path rendering.

CVE-2011-3019
Heap-based buffer overflow in Google Chrome before 17.0.963.56 allows
remote attackers to cause a denial of service or possibly have
unspecified other impact via a crafted Matroska video (aka MKV) file.

CVE-2011-3020
Unspecified vulnerability in the Native Client validator
implementation in Google Chrome before 17.0.963.56 has unknown impact
and remote attack vectors.

CVE-2011-3021
Use-after-free vulnerability in Google Chrome before 17.0.963.56
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to subframe loading.

CVE-2011-3022
translate/translate_manager.cc in Google Chrome before 17.0.963.56 and
19.x before 19.0.1036.7 uses an HTTP session to exchange data for
translation, which allows remote attackers to obtain sensitive
information by sniffing the network.

CVE-2011-3023
Use-after-free vulnerability in Google Chrome before 17.0.963.56
allows user-assisted remote attackers to cause a denial of service or
possibly have unspecified other impact via vectors related to
drag-and-drop operations.

CVE-2011-3024
Google Chrome before 17.0.963.56 allows remote attackers to cause a
denial of service (application crash) via an empty X.509 certificate.

CVE-2011-3025
Google Chrome before 17.0.963.56 does not properly parse H.264 data,
which allows remote attackers to cause a denial of service
(out-of-bounds read) via unspecified vectors.

CVE-2011-3026
Integer overflow in libpng, as used in Google Chrome before
17.0.963.56, allows remote attackers to cause a denial of service or
possibly have unspecified other impact via unknown vectors that
trigger an integer truncation.

CVE-2011-3027
Google Chrome before 17.0.963.56 does not properly perform a cast of
an unspecified variable during handling of columns, which allows
remote attackers to cause a denial of service or possibly have
unknown other impact via a crafted document.

This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/search/label/Stable%20updates");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/2f5ff968-5829-11e1-8288-00262d5ed8ee.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

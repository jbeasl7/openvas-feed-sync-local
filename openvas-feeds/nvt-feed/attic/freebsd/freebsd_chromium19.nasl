# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72445");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2012-2889", "CVE-2012-2886", "CVE-2012-2881", "CVE-2012-2876", "CVE-2012-2883", "CVE-2012-2887", "CVE-2012-2888", "CVE-2012-2894", "CVE-2012-2877", "CVE-2012-2879", "CVE-2012-2884", "CVE-2012-2874", "CVE-2012-2875", "CVE-2012-2878", "CVE-2012-2880", "CVE-2012-2882", "CVE-2012-2885", "CVE-2012-2890", "CVE-2012-2891", "CVE-2012-2892", "CVE-2012-2893", "CVE-2012-2895");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-10-03 11:11:06 -0400 (Wed, 03 Oct 2012)");
  script_name("FreeBSD Ports: chromium");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");

  script_tag(name:"insight", value:"The following package is affected: chromium

CVE-2012-2889
Cross-site scripting (XSS) vulnerability in Google Chrome before
22.0.1229.79 allows remote attackers to inject arbitrary web script or
HTML via vectors involving frames, aka 'Universal XSS (UXSS).'
CVE-2012-2886
Cross-site scripting (XSS) vulnerability in Google Chrome before
22.0.1229.79 allows remote attackers to inject arbitrary web script or
HTML via vectors related to the Google V8 bindings, aka 'Universal XSS
(UXSS).'
CVE-2012-2881
Google Chrome before 22.0.1229.79 does not properly handle plug-ins,
which allows remote attackers to cause a denial of service (DOM tree
corruption) or possibly have unspecified other impact via unknown
vectors.
CVE-2012-2876
Buffer overflow in the SSE2 optimization functionality in Google
Chrome before 22.0.1229.79 allows remote attackers to cause a denial
of service or possibly have unspecified other impact via unknown
vectors.
CVE-2012-2883
Skia, as used in Google Chrome before 22.0.1229.79, allows remote
attackers to cause a denial of service or possibly have unspecified
other impact via vectors that trigger an out-of-bounds write
operation, a different vulnerability than CVE-2012-2874.
CVE-2012-2887
Use-after-free vulnerability in Google Chrome before 22.0.1229.79
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors involving onclick events.
CVE-2012-2888
Use-after-free vulnerability in Google Chrome before 22.0.1229.79
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors involving SVG text references.

Text truncated. Please see the references for more information.

This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.nl/search/label/Stable%20updates");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/5bae2ab4-0820-11e2-be5f-00262d5ed8ee.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

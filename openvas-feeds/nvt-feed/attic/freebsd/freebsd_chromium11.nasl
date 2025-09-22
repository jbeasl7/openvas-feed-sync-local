# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71365");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-3103", "CVE-2011-3104", "CVE-2011-3105", "CVE-2011-3106", "CVE-2011-3107", "CVE-2011-3108", "CVE-2011-3110", "CVE-2011-3111", "CVE-2011-3112", "CVE-2011-3113", "CVE-2011-3114", "CVE-2011-3115");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-05-31 11:53:50 -0400 (Thu, 31 May 2012)");
  script_name("FreeBSD Ports: chromium");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");

  script_tag(name:"insight", value:"The following package is affected: chromium

CVE-2011-3103
Google V8, as used in Google Chrome before 19.0.1084.52, does not
properly perform garbage collection, which allows remote attackers to
cause a denial of service (application crash) or possibly have
unspecified other impact via crafted JavaScript code.
CVE-2011-3104
Skia, as used in Google Chrome before 19.0.1084.52, allows remote
attackers to cause a denial of service (out-of-bounds read) via
unspecified vectors.
CVE-2011-3105
Use-after-free vulnerability in the Cascading Style Sheets (CSS)
implementation in Google Chrome before 19.0.1084.52 allows remote
attackers to cause a denial of service or possibly have unspecified
other impact via vectors related to the :first-letter pseudo-element.
CVE-2011-3106
The WebSockets implementation in Google Chrome before 19.0.1084.52
does not properly handle use of SSL, which allows remote attackers to
execute arbitrary code or cause a denial of service (memory
corruption) via unspecified vectors.
CVE-2011-3107
Google Chrome before 19.0.1084.52 does not properly implement
JavaScript bindings for plug-ins, which allows remote attackers to
cause a denial of service (application crash) or possibly have
unspecified other impact via unknown vectors.
CVE-2011-3108
Use-after-free vulnerability in Google Chrome before 19.0.1084.52
allows remote attackers to execute arbitrary code via vectors related
to the browser cache.
CVE-2011-3110
The PDF functionality in Google Chrome before 19.0.1084.52 allows
remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors that trigger out-of-bounds write
operations.
CVE-2011-3111
Google V8, as used in Google Chrome before 19.0.1084.52, allows remote
attackers to cause a denial of service (invalid read operation) via
unspecified vectors.
CVE-2011-3112
Use-after-free vulnerability in the PDF functionality in Google Chrome
before 19.0.1084.52 allows remote attackers to cause a denial of
service or possibly have unspecified other impact via an invalid
encrypted document.
CVE-2011-3113
The PDF functionality in Google Chrome before 19.0.1084.52 does not
properly perform a cast of an unspecified variable during handling of
color spaces, which allows remote attackers to cause a denial of
service or possibly have unknown other impact via a crafted document.
CVE-2011-3114
Multiple buffer overflows in the PDF functionality in Google Chrome
before 19.0.1084.52 allow remote attackers to cause a denial of
service or possibly have unspecified other impact via vectors that
trigger unknown function calls.
CVE-2011-3115
Google V8, as used in Google Chrome before 19.0.1084.52, allows remote
attackers to cause a denial of service or possibly have unspecified
other impact via vectors that trigger 'type corruption.'

This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/search/label/Stable%20updates");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/219d0bfd-a915-11e1-b519-00262d5ed8ee.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

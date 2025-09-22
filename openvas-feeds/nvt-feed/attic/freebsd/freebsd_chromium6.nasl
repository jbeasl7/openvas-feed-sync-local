# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71161");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-3031", "CVE-2011-3032", "CVE-2011-3033", "CVE-2011-3034", "CVE-2011-3035", "CVE-2011-3036", "CVE-2011-3037", "CVE-2011-3038", "CVE-2011-3039", "CVE-2011-3040", "CVE-2011-3041", "CVE-2011-3042", "CVE-2011-3043", "CVE-2011-3044");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-03-12 11:35:07 -0400 (Mon, 12 Mar 2012)");
  script_name("FreeBSD Ports: chromium");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");

  script_tag(name:"insight", value:"The following package is affected: chromium

CVE-2011-3031
Use-after-free vulnerability in the element wrapper in Google V8, as
used in Google Chrome before 17.0.963.65, allows remote attackers to
cause a denial of service or possibly have unspecified other impact
via unknown vectors.

CVE-2011-3032
Use-after-free vulnerability in Google Chrome before 17.0.963.65
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to the handling of SVG
values.

CVE-2011-3033
Buffer overflow in Skia, as used in Google Chrome before 17.0.963.65,
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via unknown vectors.

CVE-2011-3034
Use-after-free vulnerability in Google Chrome before 17.0.963.65
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors involving an SVG document.

CVE-2011-3035
Use-after-free vulnerability in Google Chrome before 17.0.963.65
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors involving SVG use elements.

CVE-2011-3036
Google Chrome before 17.0.963.65 does not properly perform a cast of
an unspecified variable during handling of line boxes, which allows
remote attackers to cause a denial of service or possibly have unknown
other impact via a crafted document.

Text truncated. Please see the references for more information.

This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/search/label/Stable%20updates");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/99aef698-66ed-11e1-8288-00262d5ed8ee.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

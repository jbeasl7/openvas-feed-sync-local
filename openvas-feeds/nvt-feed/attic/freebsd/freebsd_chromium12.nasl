# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71375");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-3083", "CVE-2011-3084", "CVE-2011-3085", "CVE-2011-3086", "CVE-2011-3087", "CVE-2011-3088", "CVE-2011-3089", "CVE-2011-3090", "CVE-2011-3091", "CVE-2011-3092", "CVE-2011-3093", "CVE-2011-3094", "CVE-2011-3095", "CVE-2011-3096", "CVE-2011-3097", "CVE-2011-3099", "CVE-2011-3100");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-05-31 11:53:51 -0400 (Thu, 31 May 2012)");
  script_name("FreeBSD Ports: chromium");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");

  script_tag(name:"insight", value:"The following package is affected: chromium

CVE-2011-3083
browser/profiles/profile_impl_io_data.cc in Google Chrome before
19.0.1084.46 does not properly handle a malformed ftp URL in the SRC
attribute of a VIDEO element, which allows remote attackers to cause a
denial of service (NULL pointer dereference and application crash) via
a crafted web page.
CVE-2011-3084
Google Chrome before 19.0.1084.46 does not use a dedicated process for
the loading of links found on an internal page, which might allow
attackers to bypass intended sandbox restrictions via a crafted page.
CVE-2011-3085
The Autofill feature in Google Chrome before 19.0.1084.46 does not
properly restrict field values, which allows remote attackers to cause
a denial of service (UI corruption) and possibly conduct spoofing
attacks via vectors involving long values.
CVE-2011-3086
Use-after-free vulnerability in Google Chrome before 19.0.1084.46
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors involving a STYLE element.
CVE-2011-3087
Google Chrome before 19.0.1084.46 does not properly perform window
navigation, which has unspecified impact and remote attack vectors.
CVE-2011-3088
Google Chrome before 19.0.1084.46 does not properly draw hairlines,
which allows remote attackers to cause a denial of service
(out-of-bounds read) via unspecified vectors.
CVE-2011-3089
Use-after-free vulnerability in Google Chrome before 19.0.1084.46
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors involving tables.
CVE-2011-3090
Race condition in Google Chrome before 19.0.1084.46 allows remote
attackers to cause a denial of service or possibly have unspecified
other impact via vectors related to worker processes.

Text truncated. Please see the references for more information.

This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/search/label/Stable%20updates");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/1449af37-9eba-11e1-b9c1-00262d5ed8ee.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

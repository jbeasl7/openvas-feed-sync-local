# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71386");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-3078", "CVE-2011-3079", "CVE-2011-3080", "CVE-2011-3081", "CVE-2012-1521");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-05-31 11:53:51 -0400 (Thu, 31 May 2012)");
  script_name("FreeBSD Ports: chromium");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");

  script_tag(name:"insight", value:"The following package is affected: chromium

CVE-2011-3078
Use-after-free vulnerability in Google Chrome before 18.0.1025.168
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to the floating of
elements, a different vulnerability than CVE-2011-3081.
CVE-2011-3079
The Inter-process Communication (IPC) implementation in Google Chrome
before 18.0.1025.168 does not properly validate messages, which has
unspecified impact and attack vectors.
CVE-2011-3080
Race condition in the Inter-process Communication (IPC) implementation
in Google Chrome before 18.0.1025.168 allows attackers to bypass
intended sandbox restrictions via unspecified vectors.
CVE-2011-3081
Use-after-free vulnerability in Google Chrome before 18.0.1025.168
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to the floating of
elements, a different vulnerability than CVE-2011-3078.
CVE-2012-1521
Use-after-free vulnerability in the XML parser in Google Chrome before
18.0.1025.168 allows remote attackers to cause a denial of service or
possibly have unspecified other impact via unknown vectors.

This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/search/label/Stable%20updates");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/94c0ac4f-9388-11e1-b242-00262d5ed8ee.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

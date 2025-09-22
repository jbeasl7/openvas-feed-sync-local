# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802356");
  script_version("2024-02-15T05:05:39+0000");
  script_cve_id("CVE-2010-5073", "CVE-2010-5069");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-12-09 11:55:25 +0530 (Fri, 09 Dec 2011)");
  script_name("Google Chrome Multiple Information Disclosure Vulnerabilities - Mac OS X");
  script_xref(name:"URL", value:"http://w2spconf.com/2010/papers/p26.pdf");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain sensitive
  information about visited web pages by calling getComputedStyle method or via a crafted HTML document.");

  script_tag(name:"affected", value:"Google Chrome version 4.x on (Mac OS X).");

  script_tag(name:"insight", value:"Multiple vulnerabilities are due to implementation errors in,

  - The JavaScript failing to restrict the set of values contained in the
  object returned by the getComputedStyle method.

  - The Cascading Style Sheets (CSS) failing to handle the visited pseudo-class.");

  script_tag(name:"solution", value:"Upgrade to the Google Chrome version 5.0 or later.");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple information disclosure vulnerabilities.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

if(version_in_range(version:chromeVer, test_version:"4.0", test_version2:"4.2")){
  report = report_fixed_ver(installed_version:chromeVer, vulnerable_range:"4.0 - 4.2");
  security_message(port: 0, data: report);
}

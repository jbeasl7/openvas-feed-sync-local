# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802716");
  script_version("2023-10-13T16:09:03+0000");
  script_cve_id("CVE-2011-3047");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2012-03-20 11:24:20 +0530 (Tue, 20 Mar 2012)");
  script_name("Google Chrome 'GPU process' Multiple Vulnerabilities - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48375/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52395");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2012/03/chrome-stable-update_10.html");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to execute arbitrary code
  or cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 17.0.963.79 on Mac OS X.");
  script_tag(name:"insight", value:"The flaws are due to unspecified errors when loading certain
  plug-ins and handling GPU memory.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 17.0.963.79 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"17.0.963.79")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

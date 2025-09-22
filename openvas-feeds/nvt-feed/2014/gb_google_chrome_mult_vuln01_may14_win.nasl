# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804600");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2014-1740", "CVE-2014-1741", "CVE-2014-1742");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-05-21 14:56:09 +0530 (Wed, 21 May 2014)");
  script_name("Google Chrome Multiple Vulnerabilities - 01 (May 2014) - Windows");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2014/05/stable-channel-update.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67374");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67375");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67376");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to:

  - A use-after-free error in WebSockets.

  - An integer overflow error in the 'CharacterData::deleteData' and
  'CharacterData::replaceData' functions in dom/CharacterData.cpp.

  - A use-after-free error in the 'FrameSelection::updateAppearance' function in
  editing/FrameSelection.cpp related to editing.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct a denial of
  service and potentially execute arbitrary code.");

  script_tag(name:"affected", value:"Google Chrome version prior to 34.0.1847.137 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome 34.0.1847.137 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");


  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"34.0.1847.137")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"34.0.1847.137");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

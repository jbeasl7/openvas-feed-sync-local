# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804714");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2014-4671", "CVE-2014-0539", "CVE-2014-0537");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-07-11 10:43:50 +0530 (Fri, 11 Jul 2014)");
  script_name("Adobe Flash Player Multiple Vulnerabilities-01 (Jul 2014) - Windows");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error when handling JSONP callbacks.

  - Multiple unspecified errors.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain security
restrictions.");
  script_tag(name:"affected", value:"Adobe Flash Player before version 13.0.0.231 and 14.x before 14.0.0.145 on
Windows.");
  script_tag(name:"solution", value:"Update to Adobe Flash Player version 13.0.0.231 or 14.0.0.145 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59774");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68454");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68455");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68457");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-17.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"13.0.0.231") ||
   version_in_range(version:playerVer, test_version:"14.0.0", test_version2:"14.0.0.144"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804645");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2014-0531", "CVE-2014-0532", "CVE-2014-0533", "CVE-2014-0534",
                "CVE-2014-0535", "CVE-2014-0536");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-06-19 12:09:33 +0530 (Thu, 19 Jun 2014)");
  script_name("Adobe Flash Player Multiple Vulnerabilities-01 (Jun 2014) - Windows");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Certain unspecified input is not properly sanitised before being returned to
the user.

  - An unspecified error can be exploited to bypass certain security restrictions.

  - Another unspecified error can be exploited to corrupt memory.

  - Another unspecified error can be exploited to bypass certain security
restrictions.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct cross-site scripting
attacks, bypass certain security restrictions, and compromise a user's system.");
  script_tag(name:"affected", value:"Adobe Flash Player before version 13.0.0.223, 14.x before 14.0.0.125 on
Windows.");
  script_tag(name:"solution", value:"Update to Adobe Flash Player version 13.0.0.223 or 14.0.0.125 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb14-16.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67961");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67962");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67963");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67970");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67973");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67974");
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

if(version_is_less(version:playerVer, test_version:"13.0.0.223") ||
   version_in_range(version:playerVer, test_version:"14.0.0", test_version2:"14.0.0.124"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

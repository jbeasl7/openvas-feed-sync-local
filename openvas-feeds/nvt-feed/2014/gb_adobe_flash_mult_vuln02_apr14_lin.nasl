# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804539");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2014-0507", "CVE-2014-0508", "CVE-2014-0509");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-04-11 13:13:08 +0530 (Fri, 11 Apr 2014)");
  script_name("Adobe Flash Player Multiple Vulnerabilities - 02 (Apr 2014) - Linux");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error related to regular expressions in ActionScript.

  - An use-after-free error and multiple unspecified errors.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct cross-site scripting
attacks, bypass certain security restrictions, and compromise a user's system.");
  script_tag(name:"affected", value:"Adobe Flash Player version before 11.2.202.350 on Linux");
  script_tag(name:"solution", value:"Update to Adobe Flash Player version 11.2.202.350 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57661");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66699");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66701");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66703");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-09.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"11.2.202.350"))
{
  report = report_fixed_ver(installed_version:playerVer, fixed_version:"11.2.202.350");
  security_message(port:0, data:report);
  exit(0);
}

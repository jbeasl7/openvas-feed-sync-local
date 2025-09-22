# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804516");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2014-0503", "CVE-2014-0504");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-03-20 10:54:21 +0530 (Thu, 20 Mar 2014)");
  script_name("Adobe Flash Player Multiple Security Bypass Vulnerabilities - 01 (Feb 2014) - Linux");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple security bypass vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw are due to multiple unspecified errors.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain security
restrictions and disclose potentially sensitive information.");
  script_tag(name:"affected", value:"Adobe Flash Player version before 11.2.202.346 on Linux.");
  script_tag(name:"solution", value:"Update to Adobe Flash Player version 11.2.202.346 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57271");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66122");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66127");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-08.html");
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

if(version_is_less(version:playerVer, test_version:"11.2.202.346"))
{
  report = report_fixed_ver(installed_version:playerVer, fixed_version:"11.2.202.346");
  security_message(port:0, data:report);
  exit(0);
}

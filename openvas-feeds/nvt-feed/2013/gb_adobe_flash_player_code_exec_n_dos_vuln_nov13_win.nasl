# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804145");
  script_version("2024-06-28T15:38:46+0000");
  script_cve_id("CVE-2013-5329", "CVE-2013-5330");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2013-11-19 13:31:55 +0530 (Tue, 19 Nov 2013)");
  script_name("Adobe Flash Player Code Execution and DoS Vulnerabilities (Nov 2013) - Windows");


  script_tag(name:"summary", value:"Adobe Flash Player is prone to remote code execution (RCE) and
  denial of service (DoS) vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update to Adobe Flash Player version 11.7.700.252 or 11.9.900.152 or later.");
  script_tag(name:"insight", value:"Flaws are due to unspecified errors.");
  script_tag(name:"affected", value:"Adobe Flash Player before 11.7.700.252, 11.8.x and 11.9.x before
11.9.900.152 on Windows");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code, cause
denial of service (memory corruption) and compromise a user's system.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55527");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63680");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-26.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
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

if(version_is_less(version:playerVer, test_version:"11.7.700.252") ||
   version_in_range(version:playerVer, test_version:"11.8.0", test_version2:"11.8.800.175") ||
   version_in_range(version:playerVer, test_version:"11.9.0", test_version2:"11.9.900.151"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

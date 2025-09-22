# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804085");
  script_version("2024-11-29T15:40:53+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-0497");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-11-29 15:40:53 +0000 (Fri, 29 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-19 19:56:17 +0000 (Thu, 19 Sep 2024)");
  script_tag(name:"creation_date", value:"2014-02-05 15:02:43 +0530 (Wed, 05 Feb 2014)");
  script_name("Adobe Flash Player Arbitrary Code Execution Vulnerability (APSB14-04) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56737");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65327");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-04.html");
  script_xref(name:"URL", value:"http://krebsonsecurity.com/2014/02/adobe-pushes-fix-for-flash-zero-day-attack");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to an arbitrary code execution
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to an integer underflow condition that is triggered
  as unspecified user-supplied input is not properly validated.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to, execute
  arbitrary code and cause buffer overflow.");

  script_tag(name:"affected", value:"Adobe Flash Player versions before 11.7.700.261 and 11.8.x
  through 12.0.x before 12.0.0.44 on Windows.");

  script_tag(name:"solution", value:"Update to version 11.7.700.261, 12.0.0.44 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"11.7.700.261") ||
   version_in_range(version:vers, test_version:"11.8.0", test_version2:"12.0.0.43")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"11.7.700.261/12.0.0.44", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

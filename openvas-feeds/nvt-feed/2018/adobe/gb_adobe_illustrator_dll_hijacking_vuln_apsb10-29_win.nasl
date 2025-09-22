# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:illustrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813260");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2010-3152");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-07-12 15:32:37 +0530 (Thu, 12 Jul 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Illustrator 'DLL Hijacking' RCE Vulnerability (APSB10-29) - Windows");

  script_tag(name:"summary", value:"Adobe Illustrator is prone to a 'DLL Hijacking' remote code
  execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error where
  application allows specially crafted file to be created and load instead
  of the intended DLL");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Adobe Illustrator before CS5 15.0.2 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Illustrator CS5 15.0.2
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.adobe.com/support/security/bulletins/apsb10-29.html");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_illustrator_detect_win.nasl");
  script_mandatory_keys("Adobe/Illustrator/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
adobeVer = infos["version"];
adobePath = infos["location"];

if(version_in_range(version:adobeVer, test_version:"15.0", test_version2:"15.0.1"))
{
  report = report_fixed_ver(installed_version:adobeVer, fixed_version:"15.0.2", install_path:adobePath);
  security_message(data: report);
  exit(0);
}
exit(99);

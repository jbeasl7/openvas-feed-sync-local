# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player_chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813352");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2018-4944");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-07 20:16:00 +0000 (Thu, 07 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-05-09 12:23:30 +0530 (Wed, 09 May 2018)");
  script_name("Adobe Flash Player Within Google Chrome Security Update (APSB18-16) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a type confusion
  error.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to conduct arbitrary code execution.");

  script_tag(name:"affected", value:"Adobe Flash Player prior to 29.0.0.171
  within Google Chrome on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player for
  Google Chrome 29.0.0.171, or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb18-16.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_flash_player_within_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Chrome/MacOSX/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"29.0.0.171")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"29.0.0.171", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

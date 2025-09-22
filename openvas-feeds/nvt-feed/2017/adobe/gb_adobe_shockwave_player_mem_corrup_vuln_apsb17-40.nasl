# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:shockwave_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812092");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2017-11294");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-26 18:08:00 +0000 (Tue, 26 Dec 2017)");
  script_tag(name:"creation_date", value:"2017-11-16 11:32:08 +0530 (Thu, 16 Nov 2017)");
  script_name("Adobe Shockwave Player Memory Corruption Vulnerability (APSB17-40)");

  script_tag(name:"summary", value:"Adobe Shockwave Player is prone to a memory corruption vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to some unspecified
  memory corruption error.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code in the context of the user running the affected
  application. Failed exploit attempts will likely result in denial-of-service
  conditions.");

  script_tag(name:"affected", value:"Adobe Shockwave Player version 12.2.9.199
  and earlier on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Shockwave Player version
  12.3.1.201 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/shockwave/apsb17-40.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101836");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
playerVer = infos["version"];
playerPath = infos["location"];

if(version_is_less_equal(version:playerVer, test_version:"12.2.9.199"))
{
  report = report_fixed_ver(installed_version:playerVer, fixed_version:"12.3.1.201", install_path:playerPath);
  security_message(data:report);
  exit(0);
}
exit(0);

# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:illustrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815842");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2019-7962", "CVE-2019-8247", "CVE-2019-8248");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-11-14 12:20:15 +0530 (Thu, 14 Nov 2019)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Illustrator Multiple Vulnerabilities (APSB19-36) - Windows");

  script_tag(name:"summary", value:"Adobe Illustrator is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An insecure library loading error.

  - Multiple memory corruption errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code and escalate privileges on the affected system.");

  script_tag(name:"affected", value:"Adobe Illustrator CC 2019 23.1 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Illustrator CC 2019 version
  24.0 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/illustrator/apsb19-36.html");
  script_copyright("Copyright (C) 2019 Greenbone AG");
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

if(version_in_range(version:adobeVer, test_version:"23.0", test_version2:"23.1.0"))
{
  report = report_fixed_ver(installed_version:adobeVer, fixed_version:'24.0', install_path:adobePath);
  security_message(data: report);
  exit(0);
}
exit(0);

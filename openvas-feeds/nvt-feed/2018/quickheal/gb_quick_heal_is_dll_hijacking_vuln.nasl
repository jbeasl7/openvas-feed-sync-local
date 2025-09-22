# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:quick_heal:internet_security";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813593");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2018-8090");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-13 12:22:00 +0000 (Mon, 13 Sep 2021)");
  script_tag(name:"creation_date", value:"2018-08-02 16:39:04 +0530 (Thu, 02 Aug 2018)");

  script_name("Quick Heal Internet Security DLL Hijacking Vulnerability");

  script_tag(name:"summary", value:"Quick Heal Internet Security is prone to a DLL hijacking vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient
  validation on library loading.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to load insecure library, hijack DLL and execute arbitrary code.");

  script_tag(name:"affected", value:"Quick Heal Internet Security version 10.0.0.37");

  script_tag(name:"solution", value:"Update to version 10.0.1.46 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://github.com/kernelm0de/CVE-2018-8090");
  script_xref(name:"URL", value:"http://www.quickheal.com/quick-heal-antivirus-updates-download");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_quick_heal_is_detect.nasl");
  script_mandatory_keys("QuickHeal/InternetSecurity/Installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
quickVer = infos["version"];
quickPath = infos["location"];

if(version_is_equal(version:quickVer, test_version:"10.0.0.37"))
{
  report = report_fixed_ver(installed_version:quickVer, fixed_version:"10.0.1.46", install_path:quickPath);
  security_message(data:report);
  exit(0);
}
exit(99);

# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:powershell";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815419");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2019-1167");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-07-17 12:25:47 +0530 (Wed, 17 Jul 2019)");
  script_name("PowerShell Windows Defender Application Control Security Feature Bypass Vulnerability - Windows");

  script_tag(name:"summary", value:"This host is missing an important security
  update for PowerShell Core according to Microsoft security advisory
  CVE-2019-1167.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in Windows
  Defender Application Control (WDAC) which causes improper functioning of
  PowerShell in Constrained Language Mode.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to bypass security and access resources in an unintended way.");

  script_tag(name:"affected", value:"PowerShell Core versions 6.1 prior to 6.1.5
  and 6.2 prior to 6.2.2 on Windows.");

  script_tag(name:"solution", value:"Update PowerShell Core to version 6.1.5 or
  6.2.2 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/PowerShell/PowerShell#get-powershell");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-1167");
  script_xref(name:"URL", value:"https://github.com/PowerShell/PowerShell/security/advisories/GHSA-5frh-8cmj-gc59");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_powershell_core_detect_win.nasl");
  script_mandatory_keys("PowerShell/Win/Ver");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
psVer = infos["version"];
psPath = infos["location"];

if(psVer =~ "^6\.1\." && version_is_less(version:psVer, test_version:"6.1.5")){
  fix = "6.1.5";
}
else if(psVer =~ "^6\.2\." && version_is_less(version:psVer, test_version:"6.2.2")){
  fix = "6.2.2";
}

if(fix)
{
  report = report_fixed_ver(installed_version:psVer, fixed_version:fix, install_path:psPath);
  security_message(data:report);
  exit(0);
}
exit(0);

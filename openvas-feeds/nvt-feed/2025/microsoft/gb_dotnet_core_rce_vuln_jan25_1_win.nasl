# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834852");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2021-24112");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-26 22:27:12 +0000 (Fri, 26 Feb 2021)");
  script_tag(name:"creation_date", value:"2025-01-07 11:43:20 +0530 (Tue, 07 Jan 2025)");
  script_name(".NET Core RCE Vulnerability (January-1 2025)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft security update January 2025.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a remote code
  execution vulnerability in .NET Core.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct remote code execution.");

  script_tag(name:"affected", value:".NET Core runtime version 5.0.x prior to
  5.0.3, 3.1.x prior to 3.1.12, 2.1.x prior to 2.1.25 and .NET Core SDK version
  5.0.x prior to 5.0.103, 3.1.x prior to 3.1.112 and 2.1.x prior to 2.1.521.");

  script_tag(name:"solution", value:"Update .NET Core runtime to version 5.0.3
  or 3.1.12 or 2.1.25 or later and update .NET Core SDK to version 5.0.103 or
  3.1.112 or 2.1.521 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/dotnet/announcements/issues/176");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Windows");
  script_dependencies("gb_asp_dotnet_core_detect_win.nasl");
  script_mandatory_keys("ASP.NET/Core/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

coreVers = infos["version"];
path = infos["location"];

if(!corerunVer = get_kb_item(".NET/Core/Runtime/Ver")) {
  if(!coresdkVer = get_kb_item(".NET/Core/SDK/Ver")){
    exit(0);
  }
}

if(corerunVer)
{
  if(version_in_range_exclusive(version:corerunVer, test_version_lo:"5.0", test_version_up:"5.0.3")){
    fix = "5.0.3 or later";
  }
  else if(version_in_range_exclusive(version:corerunVer, test_version_lo:"3.1", test_version_up:"3.1.12")){
    fix = "3.1.12 or later";
  }
  else if(version_in_range_exclusive(version:corerunVer, test_version_lo:"2.1", test_version_up:"2.1.25")){
    fix = "2.1.25 or later";
  }
}

else if(coresdkVer)
{
  if(version_in_range_exclusive(version:coresdkVer, test_version_lo:"5.0", test_version_up:"5.0.103")){
    fix1 = "5.0.103 or later";
  }
  else if(version_in_range_exclusive(version:coresdkVer, test_version_lo:"3.1", test_version_up:"3.1.112")){
    fix1 = "3.1.112 or later";
  }
  else if(version_in_range_exclusive(version:coresdkVer, test_version_lo:"2.1", test_version_up:"2.1.521")){
    fix1 = "2.1.521 or later";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:"ASP .NET Core With Microsoft .NET Core runtimes " + corerunVer,
                         fixed_version:"ASP .NET Core With Microsoft .NET Core runtimes version " + fix,
                         install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

if(fix1) {
  report = report_fixed_ver(installed_version:"ASP .NET Core With Microsoft .NET Core SDK " + coresdkVer,
                         fixed_version:"ASP .NET Core With Microsoft .NET Core SDK version " + fix1,
                         install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

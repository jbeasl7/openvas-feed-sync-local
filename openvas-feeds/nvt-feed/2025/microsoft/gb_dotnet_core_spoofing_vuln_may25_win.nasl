# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836314");
  script_version("2025-05-15T05:40:37+0000");
  script_cve_id("CVE-2025-26646");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-05-15 05:40:37 +0000 (Thu, 15 May 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-13 22:15:20 +0000 (Tue, 13 May 2025)");
  script_tag(name:"creation_date", value:"2025-05-14 14:51:32 +0530 (Wed, 14 May 2025)");
  script_name(".NET Core Spoofing Vulnerability (May 2025)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft security update May 2025.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a spoofing vulnerability
  in .NET Core.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform spoofing over a network.");

  script_tag(name:"affected", value:".NET Core runtime version 8.0.x prior to
  8.0.16, 9.0.x prior to 9.0.5 and .NET Core SDK version 8.0.x prior to 8.0.409
  and 9.0.x prior to 9.0.300.");

  script_tag(name:"solution", value:"Update .NET Core runtime to version 8.0.16
  or 9.0.5 or later and update .NET Core SDK to version 8.0.409 or 9.0.300 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/9.0/9.0.5/9.0.5.md");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/8.0/8.0.16/8.0.16.md");
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

if(!coreVers || (coreVers !~ "^9\.0" && coreVers !~ "^8\.0")) {
  exit(0);
}

if(!corerunVer = get_kb_item(".NET/Core/Runtime/Ver")) {
  if(!coresdkVer = get_kb_item(".NET/Core/SDK/Ver")){
    exit(0);
  }
}

if(corerunVer)
{
  if(version_in_range_exclusive(version:corerunVer, test_version_lo:"8.0", test_version_up:"8.0.16")){
    fix = "8.0.16 or later";
  }
  else if(version_in_range_exclusive(version:corerunVer, test_version_lo:"9.0", test_version_up:"9.0.5")){
    fix = "9.0.5 or later";
  }
}

else if(coresdkVer)
{
  if(version_in_range_exclusive(version:coresdkVer, test_version_lo:"8.0", test_version_up:"8.0.409")){
    fix1 = "8.0.409 or later";
  }
  else if(version_in_range_exclusive(version:coresdkVer, test_version_lo:"9.0", test_version_up:"9.0.300")){
    fix1 = "9.0.300 or later";
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
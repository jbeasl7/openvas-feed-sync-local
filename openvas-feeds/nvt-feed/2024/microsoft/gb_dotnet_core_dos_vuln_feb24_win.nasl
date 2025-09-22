# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832674");
  script_version("2024-02-15T14:37:33+0000");
  script_cve_id("CVE-2024-21386");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 14:37:33 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 18:15:56 +0000 (Tue, 13 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-14 11:02:37 +0530 (Wed, 14 Feb 2024)");
  script_name(".NET Core DoS Vulnerability (Feb 2024) - Windows");

  script_tag(name:"summary", value:".NET Core is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a vulnerability exists in ASP.NET
  applications using SignalR where a malicious client can result in a DoS.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to cause a DoS on
  an affected system.");

  script_tag(name:"affected", value:".NET Core runtime version 6.0 prior to 6.0.26, 7.0 prior to
  7.0.15 and 8.0 prior to 8.0.1.");

  script_tag(name:"solution", value:"- Update .NET Core runtime to version 7.0.15, 6.0.268.0.1 or
  later

  - Update .NET Core SDK to version 6.0.419, 7.0.116, 8.0.102 or later");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/dotnet/announcements/issues/295");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
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

if(!coreVers || coreVers !~ "^[6|7|8]\.0"){
  exit(0);
}

if(!corerunVer = get_kb_item(".NET/Core/Runtime/Ver"))
{
  if(!codesdkVer = get_kb_item(".NET/Core/SDK/Ver")){
    exit(0);
  }
}

if(corerunVer)
{
  if(version_in_range(version:corerunVer, test_version:"6.0", test_version2:"6.0.26")){
    fix = "6.0.27 or later";
  }
  else if(version_in_range(version:corerunVer, test_version:"7.0", test_version2:"7.0.15")){
    fix = "7.0.16 or later";
  }
  else if(version_in_range(version:corerunVer, test_version:"8.0", test_version2:"8.0.1")){
    fix = "8.0.2 or later";
  }
}

else if(codesdkVer)
{
  if(version_in_range(version:codesdkVer, test_version:"6.0", test_version2:"6.0.418")){
    fix1 = "6.0.419 or later";
  }
  else if(version_in_range(version:codesdkVer, test_version:"7.0", test_version2:"7.0.115")){
    fix1 = "7.0.116 or later";
  }
  else if(version_in_range(version:codesdkVer, test_version:"8.0", test_version2:"8.0.101")){
    fix1 = "8.0.102 or later";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:"ASP .NET Core With Microsoft .NET Core runtimes " + corerunVer,
               fixed_version:"ASP .NET Core With Microsoft .NET Core runtimes version " + fix, install_path:path);
  security_message(data:report);
  exit(0);
}

else if(fix1)
{
  report = report_fixed_ver(installed_version:"ASP .NET Core With Microsoft .NET Core SDK " + codesdkVer,
               fixed_version:"ASP .NET Core With Microsoft .NET Core SDK version " + fix1, install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);

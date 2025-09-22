# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832677");
  script_version("2024-03-21T05:06:54+0000");
  script_cve_id("CVE-2024-21392", "CVE-2024-26190");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-12 17:15:57 +0000 (Tue, 12 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-03-13 11:21:28 +0530 (Wed, 13 Mar 2024)");
  script_name(".NET Core Multiple Denial of Service Vulnerabilities (KB5036452)");

  script_tag(name:"summary", value:".NET Core is prone to multiple denial of service
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-21392: .NET Denial of Service Vulnerability

  - CVE-2024-26190: Microsoft QUIC Denial of Service Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to cause denial
  of service on an affected system.");

  script_tag(name:"affected", value:".NET Core runtime version 7.0 prior to 7.0.17,
  8.0 prior to 8.0.3 and .NET Core SDK 7.0 prior to 7.0.407, 8.0 prior to 8.0.202");

  script_tag(name:"solution", value:"- Update .NET Core runtime to version 7.0.17 or 8.0.3
  and .NET Core SDK to 7.0.407 or 8.0.202 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/8.0/8.0.3/8.0.3.md");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/7.0/7.0.17/7.0.17.md");
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

if(!coreVers || coreVers !~ "^[7|8]\.0"){
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
  if(version_in_range(version:corerunVer, test_version:"7.0", test_version2:"7.0.16")){
    fix = "7.0.17 or later";
  }
  else if(version_in_range(version:corerunVer, test_version:"8.0", test_version2:"8.0.2")){
    fix = "8.0.3 or later";
  }
}

else if(codesdkVer)
{
  if(version_in_range(version:codesdkVer, test_version:"7.0", test_version2:"7.0.406")){
    fix1 = "7.0.407 or later";
  }
  else if(version_in_range(version:codesdkVer, test_version:"8.0", test_version2:"8.0.201")){
    fix1 = "8.0.202 or later";
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

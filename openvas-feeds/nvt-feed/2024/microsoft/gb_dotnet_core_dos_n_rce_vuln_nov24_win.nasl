# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834533");
  script_version("2025-03-07T15:40:19+0000");
  script_cve_id("CVE-2024-43498", "CVE-2024-43499");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-07 15:40:19 +0000 (Fri, 07 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-12 18:15:24 +0000 (Tue, 12 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-11-13 10:57:53 +0530 (Wed, 13 Nov 2024)");
  script_name(".NET Core Multiple Vulnerabilities (Nov 2024)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft security update November 2024.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-43498: .NET Remote Code Execution Vulnerability.

  - CVE-2024-43499: .NET Denial of Service Vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct remote code execution and denial of service attacks.");

  script_tag(name:"affected", value:".NET Core runtime version 9.0.x prior to
  9.0.0 and .NET Core SDK version 9.0.x prior to 9.0.100.");

  script_tag(name:"solution", value:"Update .NET Core runtime to version 9.0.0
  or later and update .NET Core SDK to version 9.0.100 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/9.0/9.0.0/9.0.0.md");
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

if(!coreVers || coreVers !~ "^9\.0") {
  exit(0);
}

if(!corerunVer = get_kb_item(".NET/Core/Runtime/Ver")) {
  if(!coresdkVer = get_kb_item(".NET/Core/SDK/Ver")){
    exit(0);
  }
}

if(corerunVer) {
  ## .NET 9.0.0.RC.2 or earlier is vulnerable
  if(corerunVer =~ "^9\.0\.0" && corerunVer !~ "^9\.0\.0$"){
    fix = "9.0.0 or later";
  }
}

else if(coresdkVer) {
  if(coresdkVer =~ "^9\.0" && version_is_less(version:coresdkVer, test_version:"9.0.100")) {
    fix1 = "9.0.100 or later";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:"ASP .NET Core With Microsoft .NET Core runtimes " + corerunVer,
               fixed_version:"ASP .NET Core With Microsoft .NET Core runtimes version " + fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

else if(fix1) {
  report = report_fixed_ver(installed_version:"ASP .NET Core With Microsoft .NET Core SDK " + coresdkVer,
               fixed_version:"ASP .NET Core With Microsoft .NET Core SDK version " + fix1, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);


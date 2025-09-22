# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832996");
  script_version("2024-05-21T05:05:23+0000");
  script_cve_id("CVE-2024-30045", "CVE-2024-30046");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-05-21 05:05:23 +0000 (Tue, 21 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-14 17:17:17 +0000 (Tue, 14 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-15 15:31:32 +0530 (Wed, 15 May 2024)");
  script_name(".NET Core Multiple Vulnerabilities (KB5038351)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5038351.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-30045: .NET Remote Code Execution Vulnerability

  - CVE-2024-30046: .NET Denial of Service Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute arbitrary commands and conduct denial of service attacks.");

  script_tag(name:"affected", value:".NET Core runtime 7.x before 7.0.19, 8.x
  before 8.0.5 and .NET Core SDK 7.x before 7.0.409, 8.x before 8.0.300.");

  script_tag(name:"solution", value:"Update .NET Core runtime to version 7.0.19
  or 8.0.5 or later or update .NET Core SDK to version 7.0.409 or 8.0.300 later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/7.0/7.0.19/7.0.19.md");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/8.0/8.0.5/8.0.5.md");
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

if(!coreVers || (coreVers !~ "^7\.0" && coreVers !~ "^8\.0")) {
  exit(0);
}

if(!corerunVer = get_kb_item(".NET/Core/Runtime/Ver")) {
  if(!codesdkVer = get_kb_item(".NET/Core/SDK/Ver")){
    exit(0);
  }
}

if(corerunVer) {
  if(corerunVer =~ "^7\.0" && version_is_less(version:corerunVer, test_version:"7.0.19") ||
     corerunVer =~ "^8\.0" && version_is_less(version:corerunVer, test_version:"8.0.5")) {
    fix = "7.0.19 or 8.0.5 or later";
  }
}

else if(codesdkVer) {
  if(corerunVer =~ "^7\.0" && version_is_less(version:corerunVer, test_version:"7.0.409") ||
     corerunVer =~ "^8\.0" && version_is_less(version:corerunVer, test_version:"8.0.300")) {
    fix1 = "7.0.409 or 8.0.300 or later";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:"ASP .NET Core With Microsoft .NET Core runtimes " + corerunVer,
               fixed_version:"ASP .NET Core With Microsoft .NET Core runtimes version " + fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

else if(fix1) {
  report = report_fixed_ver(installed_version:"ASP .NET Core With Microsoft .NET Core SDK " + codesdkVer,
               fixed_version:"ASP .NET Core With Microsoft .NET Core SDK version " + fix1, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);


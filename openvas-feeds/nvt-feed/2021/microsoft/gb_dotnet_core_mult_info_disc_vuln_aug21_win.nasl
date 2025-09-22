# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818182");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2021-26423", "CVE-2021-34532");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-19 16:56:00 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-11 17:35:18 +0530 (Wed, 11 Aug 2021)");
  script_name(".NET Core Denial of Service And Information Disclosure Vulnerabilities - Windows");

  script_tag(name:"summary", value:".NET Core is prone to a denial of service (DoS) and
  an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - .NET (Core) server applications providing WebSocket endpoints could be
    tricked into endlessly looping while trying to read a single WebSocket frame.

  - A JWT token is logged if it cannot be parsed.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to disclose sensitive information and also cause a denial of service
  condition.");

  script_tag(name:"affected", value:".NET Core runtime 5.0 before 5.0.9, 3.1 before
  3.1.18, and 2.1 before 2.1.29 and .NET Core SDK 5.0 before 5.0.206, 3.1 before 3.1.118,
  and 2.1 before 2.1.525.");

  script_tag(name:"solution", value:"Upgrade .NET Core runtimes to versions
  5.0.9 or 3.1.18 or 2.1.29 or later or upgrade .NET Core SDK to versions 5.0.206
  or 5.0.303 or 3.1.118 or 3.1.412 or 2.1.525 or 2.1.817 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/dotnet/announcements/issues/195");
  script_xref(name:"URL", value:"https://github.com/dotnet/announcements/issues/194");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
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

if(!coreVers || coreVers !~ "^([3|2]\.1|5\.0)")
  exit(0);

if(!corerunVer = get_kb_item(".NET/Core/Runtime/Ver")) {
  if(!codesdkVer = get_kb_item(".NET/Core/SDK/Ver")) {
    exit(0);
  }
}

if(corerunVer) {
  if(version_in_range(version:corerunVer, test_version:"5.0", test_version2:"5.0.8")) {
    fix = "5.0.9";
  }

  else if(version_in_range(version:corerunVer, test_version:"3.1", test_version2:"3.1.17")) {
    fix = "3.1.18";
  }

  else if(version_in_range(version:corerunVer, test_version:"2.1", test_version2:"2.1.28")) {
    fix = "2.1.29";
  }
}

else if(codesdkVer) {
  if(version_in_range(version:codesdkVer, test_version:"5.0", test_version2:"5.0.205")) {
    fix1 = "5.0.206 (for Visual Studio 2019 v16.8) or SDK 5.0.303 (for Visual Studio 2019 V16.10)";
  }

  else if(version_in_range(version:codesdkVer, test_version:"3.1", test_version2:"3.1.117")) {
    fix1 = "3.1.118 (for Visual Studio 2019 v16.4) or 3.1.412 (for Visual Studio 2019 v16.7 or later)";
  }

  else if(version_in_range(version:codesdkVer, test_version:"2.1", test_version2:"2.1.524")) {
    fix1 = "2.1.525 (for Visual Studio 2019 v15.9) or 2.1.817";
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

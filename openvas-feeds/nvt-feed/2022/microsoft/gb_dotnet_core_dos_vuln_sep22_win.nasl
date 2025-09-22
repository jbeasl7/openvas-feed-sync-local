# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826454");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2022-38010");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-13 20:43:00 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-14 08:52:24 +0530 (Wed, 14 Sep 2022)");
  script_name(".NET Core Denial of Service Vulnerability - Windows");

  script_tag(name:"summary", value:".NET Core and is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to stack overflow
  vulnerability in .NET.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to conduct DOS attack.");

  script_tag(name:"affected", value:".NET Core runtime 6.0 before 6.0.9, 3.1
  before 3.1.29 and .NET Core SDK before 6.0.109, 6.0.304, 6.0.401, 3.1 before
  3.1.423.");

  script_tag(name:"solution", value:"Upgrade .NET Core runtimes to versions
  6.0.9 or 3.1.29 or later or upgrade .NET Core SDK to versions 6.0.109 or
  6.0.304 or 6.0.401 or 3.1.423 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/6.0/6.0.9/6.0.9.md");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/3.1/3.1.29/3.1.29.md");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
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

if(!coreVers || coreVers !~ "^(3\.1|6\.0)")
  exit(0);

if(!corerunVer = get_kb_item(".NET/Core/Runtime/Ver")) {
  if(!codesdkVer = get_kb_item(".NET/Core/SDK/Ver")) {
    exit(0);
  }
}

if(corerunVer) {
  if(version_in_range(version:corerunVer, test_version:"6.0", test_version2:"6.0.8")) {
    fix = "6.0.9 or later";
  }

  else if(version_in_range(version:corerunVer, test_version:"3.1", test_version2:"3.1.28")) {
    fix = "3.1.29 or later";
  }
}

else if(codesdkVer) {
  if(version_in_range(version:codesdkVer, test_version:"6.0", test_version2:"6.0.108")) {
    fix1 = "6.0.109";
  }

  else if(version_in_range(version:codesdkVer, test_version:"6.0.300", test_version2:"6.0.303")) {
    fix1 = "6.0.304";
  }

  else if(codesdkVer == "6.0.400") {
    fix1 = "6.0.401";
  }

  else if(version_in_range(version:codesdkVer, test_version:"3.1", test_version2:"3.1.422")) {
    fix1 = "3.1.423";
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

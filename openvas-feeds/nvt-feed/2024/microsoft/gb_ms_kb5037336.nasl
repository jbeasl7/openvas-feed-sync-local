# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832925");
  script_version("2024-08-30T05:05:38+0000");
  script_cve_id("CVE-2024-21409");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-08-30 05:05:38 +0000 (Fri, 30 Aug 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-09 17:15:34 +0000 (Tue, 09 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-04-11 14:02:11 +0530 (Thu, 11 Apr 2024)");
  script_name(".NET Core Privilege Escalation Vulnerability (KB5037336)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5037336.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an use-after-free
  vulnerability existing in WPF.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to gain elevated privileges.");

  script_tag(name:"affected", value:".NET Core runtime prior to version 6.0.29
  and .NET Core SDK prior to version 6.0.129.");

  script_tag(name:"solution", value:"Update .NET Core runtime to version 6.0.29
  or later and update .NET Core SDK to version 6.0.129 later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/6.0/6.0.29/6.0.29.md");
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

if(!coreVers || coreVers !~ "^7\.0") {
  exit(0);
}

if(!corerunVer = get_kb_item(".NET/Core/Runtime/Ver")) {
  if(!codesdkVer = get_kb_item(".NET/Core/SDK/Ver")){
    exit(0);
  }
}

if(corerunVer) {
  if(corerunVer =~ "^6\.0" && version_is_less(version:corerunVer, test_version:"6.0.29")) {
    fix = "6.0.29 or later";
  }
}

else if(codesdkVer) {
  if(codesdkVer =~ "^6\.0" && version_is_less(version:codesdkVer, test_version:"6.0.129")) {
    fix1 = "6.0.129 or later";
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


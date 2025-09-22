# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834418");
  script_version("2024-08-20T05:05:37+0000");
  script_cve_id("CVE-2024-38168", "CVE-2024-38167");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-08-20 05:05:37 +0000 (Tue, 20 Aug 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-13 18:15:24 +0000 (Tue, 13 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-14 10:47:19 +0530 (Wed, 14 Aug 2024)");
  script_name(".NET Core Multiple Vulnerabilities (KB5042132)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5042132.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-38168: A vulnerability exists in .NET when an attacker through unauthenticated requests may trigger a Denial of Service in ASP.NET HTTP.sys web server.

  - CVE-2024-38167: A vulnerability exists in .NET runtime TlsStream which may result in Information Disclosure.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to disclose sensitive information and conduct denial of service attacks.");

  script_tag(name:"affected", value:".NET Core runtime prior to version 8.0.8
  and .NET Core SDK prior to version 8.0.304.");

  script_tag(name:"solution", value:"Update .NET Core runtime to version 8.0.8
  or later and update .NET Core SDK to version 8.0.304 later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/8.0/8.0.8/8.0.8.md");
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

if(!coreVers || coreVers !~ "^8\.0") {
  exit(0);
}

if(!corerunVer = get_kb_item(".NET/Core/Runtime/Ver")) {
  if(!codesdkVer = get_kb_item(".NET/Core/SDK/Ver")){
    exit(0);
  }
}

if(corerunVer) {
  if(corerunVer =~ "^8\.0" && version_is_less(version:corerunVer, test_version:"8.0.8")) {
    fix = "8.0.8 or later";
  }
}

if(codesdkVer) {
  if(codesdkVer =~ "^8\.0" && version_is_less(version:codesdkVer, test_version:"8.0.304")) {
    fix1 = "8.0.304 or later";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:"ASP .NET Core With Microsoft .NET Core runtimes " + corerunVer,
               fixed_version:"ASP .NET Core With Microsoft .NET Core runtimes version " + fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

if(fix1) {
  report = report_fixed_ver(installed_version:"ASP .NET Core With Microsoft .NET Core SDK " + codesdkVer,
               fixed_version:"ASP .NET Core With Microsoft .NET Core SDK version " + fix1, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);


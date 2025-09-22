# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:.netcore_sdk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815171");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2019-1075");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-19 15:34:00 +0000 (Fri, 19 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-11 09:58:50 +0530 (Thu, 11 Jul 2019)");
  script_name(".NET Core SDK Spoofing Vulnerability (Jul 2019)");

  script_tag(name:"summary", value:"ASP.NET Core SDK is prone to spoofing vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in ASP.NET
  Core that could lead to an open redirect.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct Spoofing attack.");

  script_tag(name:"affected", value:"ASP.NET Core SDK 2.1.x prior to version
  2.1.508 and 2.2.x prior to version 2.2.108");

  script_tag(name:"solution", value:"Upgrade to ASP.NET Core SDK 2.1.508 or
  2.2.108 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/master/release-notes/2.2/2.2.6/2.2.6.md");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/108984");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/master/release-notes/2.1/2.1.12/2.1.12.md");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1075");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Windows");
  script_dependencies("gb_asp_dotnet_core_detect_win.nasl");
  script_mandatory_keys(".NET/Core/SDK/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

coreVers = infos["version"];
path = infos["location"];

if (coreVers =~ "^2\.1" && version_is_less(version:coreVers, test_version:"2.1.508")) {
  fix = "2.1.508";
}

else if (coreVers =~ "^2\.2" && version_is_less(version:coreVers, test_version:"2.2.108")) {
  fix = "2.2.108";
}

if(fix) {
  report = report_fixed_ver(installed_version:coreVers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

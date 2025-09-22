# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:.netcore_sdk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814758");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2019-0657");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-07 16:55:00 +0000 (Thu, 07 Mar 2019)");
  script_tag(name:"creation_date", value:"2019-02-14 12:17:57 +0530 (Thu, 14 Feb 2019)");
  script_name(".NET Core SDK Spoofing Vulnerability (Feb 2019)");

  script_tag(name:"summary", value:"ASP.NET Core SDK is prone to a spoofing vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in .Net
  Framework API's in the way they parse URL's.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct spoofing attacks.");

  script_tag(name:"affected", value:"ASP.NET Core SDK 1.x prior to version 1.1.12,
  2.1.x prior to version 2.1.504 and 2.2.x prior to version 2.2.104");

  script_tag(name:"solution", value:"Upgrade to ASP.NET Core SDK 1.1.12 or
  2.1.504 or 2.2.104 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/master/release-notes/2.2/2.2.2/2.2.2.md");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/106890");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/master/release-notes/2.1/2.1.8/2.1.8.md");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/master/release-notes/1.1/1.1.11/1.1.11.md");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0657");

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

if(coreVers =~ "^1\." && version_is_less(version:coreVers, test_version:"1.1.12")) {
  fix = "1.1.12";
}

else if (coreVers =~ "^2\.1" && version_is_less(version:coreVers, test_version:"2.1.504")) {
  fix = "2.1.504";
}

else if (coreVers =~ "^2\.2" && version_is_less(version:coreVers, test_version:"2.2.104")) {
  fix = "2.2.104";
}

if(fix) {
  report = report_fixed_ver(installed_version:coreVers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

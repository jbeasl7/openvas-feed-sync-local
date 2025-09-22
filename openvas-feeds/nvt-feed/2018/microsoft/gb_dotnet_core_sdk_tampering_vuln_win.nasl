# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:.netcore_sdk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814296");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2018-8416");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-11-15 17:19:11 +0530 (Thu, 15 Nov 2018)");
  script_name("ASP.NET Core SDK Tampering Vulnerability (Nov 2018) - Windows");

  script_tag(name:"summary", value:"ASP.NET Core SDK is prone to a tampering vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error when .NET
  Core improperly handles specially crafted files.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to write arbitrary files and directories to certain locations on a vulnerable
  system.");

  script_tag(name:"affected", value:"ASP.NET Core SDK 2.1 prior to version 2.1.500");

  script_tag(name:"solution", value:"Upgrade to ASP.NET Core 2.1.500 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/master/release-notes/2.1/2.1.6/2.1.6.md#notable-changes-in-216");
  script_xref(name:"URL", value:"https://github.com/dotnet/corefx/pull/32127");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
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

if(coreVers =~ "^2\.1" && version_is_less(version:coreVers, test_version:"2.1.500")) {
  report = report_fixed_ver(installed_version:coreVers, fixed_version:"2.1.500", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:.netcore_sdk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818325");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2021-31957");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-01 23:15:00 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2021-06-10 10:10:36 +0530 (Thu, 10 Jun 2021)");
  script_name(".NET Core SDK Denial of Service Vulnerability (Jun 2021)");

  script_tag(name:"summary", value:"ASP.NET Core SDK is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified error in
  the Microsoft ASP.NET Core SDK");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct a denial of service attack on the affected system.");

  script_tag(name:"affected", value:"ASP.NET Core SDK 3.1.x prior to 3.1.116 version
  and 5.0.x prior to 5.0.204");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the
  references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/5.0/5.0.7/5.0.7.md");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/3.1/3.1.16/3.1.16.md");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31957");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
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

if (coreVers =~ "^5\.0" && version_is_less(version:coreVers, test_version:"5.0.204")) {
  fix = "5.0.204";
}

else if (coreVers =~ "^3\.1" && version_is_less(version:coreVers, test_version:"3.1.116")) {
  fix = "3.1.116";
}

if(fix) {
  report = report_fixed_ver(installed_version:coreVers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

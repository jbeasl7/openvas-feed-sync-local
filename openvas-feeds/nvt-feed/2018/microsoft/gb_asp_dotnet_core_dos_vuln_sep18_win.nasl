# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only
CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814208");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2018-8409");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-04 17:54:00 +0000 (Tue, 04 Oct 2022)");
  script_tag(name:"creation_date", value:"2018-09-14 11:19:31 +0530 (Fri, 14 Sep 2018)");
  script_name("ASP.NET Core 'System.IO.Pipelines' Denial of Service Vulnerability (Sep 2018) - Windows");

  script_tag(name:"summary", value:"ASP.NET Core is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error on how
  'System.IO.Pipelines' handles requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to cause a denial of service against an application that is leveraging
  System.IO.Pipelines.");

  script_tag(name:"affected", value:"ASP.NET Core 2.1 prior to version 2.1.4");

  script_tag(name:"solution", value:"Upgrade to ASP.NET Core 2.1.4 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://blogs.msdn.microsoft.com/dotnet/2018/09/11/net-core-september-2018-update");
  script_xref(name:"URL", value:"https://github.com/aspnet/Announcements/issues/316");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Windows");
  script_dependencies("gb_asp_dotnet_core_detect_win.nasl");
  script_mandatory_keys("ASP.NET/Core/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE, version_regex:"[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

coreVers = infos["version"];
path = infos["location"];

if(coreVers =~ "^2\.1" && version_is_less(version:coreVers, test_version:"2.1.4")) {
  report = report_fixed_ver(installed_version:coreVers, fixed_version:"2.1.4", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

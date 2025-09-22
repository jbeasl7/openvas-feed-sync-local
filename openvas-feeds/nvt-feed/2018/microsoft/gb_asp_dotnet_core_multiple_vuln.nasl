# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812950");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2018-0785", "CVE-2018-0784");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-02-27 12:03:33 +0530 (Tue, 27 Feb 2018)");
  script_name("ASP.NET Core Multiple Vulnerabilities - Windows");

  script_tag(name:"summary", value:"ASP.NET Core is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in the ASP.NET Core web application, created using vulnerable
    project templates, which fails to properly sanitize web requests.

  - An error in the individual authentication templates for ASP.NET Core.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  who successfully exploited these vulnerabilities to change the recovery codes
  associated with the victim's user account without his/her consent.");

  script_tag(name:"affected", value:"ASP.NET Core 2.0 with .NET SDK version
  2.0.0, 2.0.2, 2.0.3, 2.1.2 and 2.1.3");

  script_tag(name:"solution", value:"Upgrade to ASP.NET Core 2.0 with .NET SDK
  version 2.1.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://github.com/aspnet/Announcements/issues/284");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102379");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102377");
  script_xref(name:"URL", value:"https://github.com/aspnet/Announcements/issues/285");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Windows");
  script_dependencies("gb_asp_dotnet_core_detect_win.nasl");
  script_mandatory_keys("ASP.NET/Core/Ver", ".NET/Core/SDK/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

coreVers = infos["version"];
path = infos["location"];

if(coreVers =~ "^2\.0") {
  sdkVer = get_kb_item(".NET/Core/SDK/Ver");
  affected = make_list("2.0.0", "2.0.2", "2.0.3", "2.1.2", "2.1.3");
  foreach affecVer (affected) {
    if(sdkVer == affecVer) {
      report = report_fixed_ver(installed_version:"ASP .NET Core With Microsoft .NET Core SDK " + sdkVer,
                                fixed_version:"ASP .NET Core With Microsoft .NET Core SDK 2.1.4", install_path:path);
      security_message(port:0, data:report);
      exit(0);
    }
  }
}

exit(99);

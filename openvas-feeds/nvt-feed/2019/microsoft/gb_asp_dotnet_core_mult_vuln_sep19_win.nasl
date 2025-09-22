# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:asp.net_core" ;

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815617");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2019-1302", "CVE-2019-1301");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-12 17:29:00 +0000 (Thu, 12 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-11 08:59:02 +0530 (Wed, 11 Sep 2019)");
  script_name(".NET Core Multiple Vulnerabilities (Sep 2019)");

  script_tag(name:"summary", value:"ASP.NET Core is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error when .NET Core improperly handles web requests.

  - An error when a ASP.NET Core web application, created using vulnerable project
    templates fails to properly sanitize web requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to cause a denial of service condition and perform content injection attacks
  and run script in the security context of the logged-on user.");

  script_tag(name:"affected", value:"ASP.NET Core 2.1.x prior to version
  2.1.13 and 2.2.x prior to version 2.2.7");

  script_tag(name:"solution", value:"Upgrade to ASP.NET Core SDK 2.1.13 or
  2.2.7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/master/release-notes/2.2/2.2.7/2.2.7.md");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/master/release-notes/2.1/2.1.13/2.1.13.md");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-1302");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-1301");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
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

if (coreVers =~ "^2\.1" && version_is_less(version:coreVers, test_version:"2.1.13")) {
  fix = "2.1.13";
}

else if (coreVers =~ "^2\.2" && version_is_less(version:coreVers, test_version:"2.2.7")) {
  fix = "2.2.7";
}

if(fix) {
  report = report_fixed_ver(installed_version:coreVers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:7-zip:7-zip";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834902");
  script_version("2025-04-11T15:45:04+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2025-0411");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-12 18:14:13 +0000 (Wed, 12 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-01-21 17:17:02 +0530 (Tue, 21 Jan 2025)");
  script_name("7-Zip Mark-of-the-Web Bypass Vulnerability (Jan 2025) - Windows");

  script_tag(name:"summary", value:"7zip is prone to a mark-of-the-web bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an incomplete
  implementation or design oversight in 7-Zip's handling of the Mark-of-the-Web
  mechanism when extracting files from archives.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to bypass the 'Mark-of-the-Web' security feature in Windows and execute
  arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"7zip version prior to 24.09 on Windows.");

  script_tag(name:"solution", value:"Update to version 24.09 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-25-045/");
  script_xref(name:"URL", value:"https://www.trendmicro.com/en_us/research/25/a/cve-2025-0411-ukrainian-organizations-targeted.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_7zip_detect_portable_win.nasl");
  script_mandatory_keys("7zip/Win/Ver");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"24.09")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"24.09", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

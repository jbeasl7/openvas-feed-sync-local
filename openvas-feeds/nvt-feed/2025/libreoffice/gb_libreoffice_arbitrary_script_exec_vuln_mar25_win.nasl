# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834978");
  script_version("2025-04-11T15:45:04+0000");
  script_cve_id("CVE-2025-1080");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-03-05 10:44:09 +0530 (Wed, 05 Mar 2025)");
  script_name("LibreOffice Arbitrary Script Execution Vulnerability (Mar 2025) - Windows");

  script_tag(name:"summary", value:"LibreOffice is prone to an arbitrary script
  execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to improper handling of
  the office URI schemes in LibreOffice, specifically the
  'vnd.libreoffice.command' scheme.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute internal macros with arbitrary arguments.");

  script_tag(name:"affected", value:"LibreOffice version 24.8 before 24.8.5 and
  25.2 before 25.2.1 on Windows.");

  script_tag(name:"solution", value:"Update to version 24.8.5 or 25.2.1 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2025-1080");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_libre_office_detect_win.nasl");
  script_mandatory_keys("LibreOffice/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range_exclusive(version: version, test_version_lo: "24.8", test_version_up: "24.8.5")) {
  fix = "24.8.5";
}

if(version_in_range_exclusive(version: version, test_version_lo: "25.2", test_version_up: "25.2.1")) {
  fix = "25.2.1";
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

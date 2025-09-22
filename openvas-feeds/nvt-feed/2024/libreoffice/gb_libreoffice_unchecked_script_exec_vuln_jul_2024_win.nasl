# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834248");
  script_version("2024-07-25T05:05:41+0000");
  script_cve_id("CVE-2024-3044");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-25 05:05:41 +0000 (Thu, 25 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-12 15:44:36 +0530 (Fri, 12 Jul 2024)");
  script_name("LibreOffice Unchecked Script Execution Vulnerability (Jul 2024) - Windows");

  script_tag(name:"summary", value:"LibreOffice is prone to an unchecked
  script execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unchecked script
  execution error in LibreOffice Graphics on-click binding.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to create a document which without prompt will execute scripts built-into
  LibreOffice on clicking a graphic.");

  script_tag(name:"affected", value:"LibreOffice prior to version 7.6.7,
  24.2.x prior to 24.2.3 on Windows.");

  script_tag(name:"solution", value:"Update to version 7.6.7 or 24.2.3
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/CVE-2024-3044");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
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

if(version_is_less(version:version, test_version:"7.6.7")) {
  fix = "7.6.7";
}

if(version_in_range(version:version, test_version:"24.2.0", test_version2:"24.2.2")) {
  fix = "24.2.3";
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

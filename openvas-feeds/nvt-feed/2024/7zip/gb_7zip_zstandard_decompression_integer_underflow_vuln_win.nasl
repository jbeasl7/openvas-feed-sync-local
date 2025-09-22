# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:7-zip:7-zip";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834786");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2024-11477");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-11 19:23:36 +0000 (Wed, 11 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-11-27 21:30:03 +0530 (Wed, 27 Nov 2024)");
  script_name("7-Zip Zstandard Decompression Integer Underflow Vulnerability - Windows");

  script_tag(name:"summary", value:"7zip is prone to a zstandard decompression
  integer underflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to lack of input data
  validation in the Zstandard decompression feature in 7-Zip.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform remote code execution.");

  script_tag(name:"affected", value:"7zip version prior to 24.07 on Windows.");

  script_tag(name:"solution", value:"Update to version 24.07 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-24-1532/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"24.07")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"24.07", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

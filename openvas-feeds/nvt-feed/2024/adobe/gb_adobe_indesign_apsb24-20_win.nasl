# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:indesign_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832933");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2024-20766");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-10 13:51:37 +0000 (Wed, 10 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-04-14 20:15:50 +0530 (Sun, 14 Apr 2024)");
  script_name("Adobe InDesign Out-of-bounds Reads Vulnerability (APSB24-20) - Windows");

  script_tag(name:"summary", value:"Adobe InDesign is prone to an out-of-bounds
  read vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an out-of-bounds
  read error.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to cause a memory leak.");

  script_tag(name:"affected", value:"Adobe InDesign 18.x through 18.5.1 and 19.x
  through 19.2 on Windows.");

  script_tag(name:"solution", value:"Update to version 18.5.2 or 19.3 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/indesign/apsb24-20.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_indesign_detect.nasl");
  script_mandatory_keys("Adobe/InDesign/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version: vers, test_version: "18.0", test_version2: "18.5.1")) {
  fix = "18.5.2";
}

if(version_in_range(version: vers, test_version: "19.0", test_version2: "19.2")) {
  fix = "19.3";
}

if(fix) {
  report = report_fixed_ver(installed_version: vers, fixed_version: fix, install_path: path);
  security_message(port:0, data: report);
  exit(0);
}

exit(99);

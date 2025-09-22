# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128007");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2023-42938");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-09 14:48:51 +0000 (Mon, 09 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-04-15 12:00:00 +0530 (Mon, 15 Apr 2024)");
  script_name("Apple iTunes < 12.13.1 Local Privilege Escalation Vulnerability (HT214091) - Windows");

  script_tag(name:"summary", value:"Apple iTunes is prone to a local privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a logic issue.");

  script_tag(name:"impact", value:"Successful exploitation with an unknown input leads to a local
  privilege escalation vulnerability.");

  script_tag(name:"affected", value:"Apple iTunes before 12.13.1 on Windows.");

  script_tag(name:"solution", value:"Update to version 12.13.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT214091");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_apple_itunes_smb_login_detect.nasl");
  script_mandatory_keys("apple/itunes/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"12.13.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"12.13.1", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

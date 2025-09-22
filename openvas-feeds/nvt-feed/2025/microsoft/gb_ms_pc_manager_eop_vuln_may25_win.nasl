# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:pc_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836316");
  script_version("2025-05-15T05:40:37+0000");
  script_cve_id("CVE-2025-29975");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-05-15 05:40:37 +0000 (Thu, 15 May 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-13 17:15:58 +0000 (Tue, 13 May 2025)");
  script_tag(name:"creation_date", value:"2025-05-14 14:51:32 +0530 (Wed, 14 May 2025)");
  script_name("Microsoft PC Manager Elevation of Privilege Vulnerability (May 2025) - Windows");

  script_tag(name:"summary", value:"Microsoft PC Manager is prone to an
  elevation of privilege vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an elevation of
  privilege vulnerability in Microsoft PC Manager.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to elevate privileges.");

  script_tag(name:"affected", value:"Microsoft PC Manager prior to version  3.16.1.0 on Microsoft Windows.");

  script_tag(name:"solution", value:"Update to version 3.16.1.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-29975");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");

  script_dependencies("gb_ms_pc_manager_detect_win.nasl");
  script_mandatory_keys("PCManager/Win/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"3.16.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.16.1.0", install_path: location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

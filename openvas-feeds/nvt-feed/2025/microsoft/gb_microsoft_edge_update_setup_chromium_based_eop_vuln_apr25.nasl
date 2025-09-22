# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:edge_update_setup";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836136");
  script_version("2025-04-24T05:40:01+0000");
  script_cve_id("CVE-2025-21399");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:01 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-17 20:15:46 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2025-04-15 11:15:42 +0530 (Tue, 15 Apr 2025)");
  script_name("Microsoft Edge Update Setup (Chromium-based) Elevation of Privilege Vulnerability (Apr 2025)");

  script_tag(name:"summary", value:"Microsoft Edge Update Setup (Chromium-based)
  is prone to an elevation of privilege vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an elevation of
  privilege vulnerability in Microsoft Edge Update Setup.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to elevate privileges.");

  script_tag(name:"affected", value:"Microsoft Edge Update Setup (Chromium-based) prior to version 1.3.195.43.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please
  see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21399");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_edge_update_setup_chromium_based_detect_win.nasl");
  script_mandatory_keys("Mseus/Win/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"1.3.195.43")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.3.195.43", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
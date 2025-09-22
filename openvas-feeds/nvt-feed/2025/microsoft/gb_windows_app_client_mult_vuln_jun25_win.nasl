# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:windows_app";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836419");
  script_version("2025-06-13T05:40:07+0000");
  script_cve_id("CVE-2025-29967", "CVE-2025-29966");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-06-13 05:40:07 +0000 (Fri, 13 Jun 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-13 17:15:57 +0000 (Tue, 13 May 2025)");
  script_tag(name:"creation_date", value:"2025-06-11 15:47:17 +0530 (Wed, 11 Jun 2025)");
  script_name("Windows App Client Multiple Vulnerabilities (Jun 2025) - Windows");

  script_tag(name:"summary", value:"Windows App Client is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform remote code execution.");

  script_tag(name:"affected", value:"Microsoft Windows App Client prior to version 2.0.503.0 on Microsoft Windows.");

  script_tag(name:"solution", value:"Update to version 2.0.503.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/windows-app/whats-new?tabs=windows");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");

  script_dependencies("gb_windows_app_client_detect_win.nasl");
  script_mandatory_keys("WAClient/Win/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"2.0.503.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.503.0", install_path: location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

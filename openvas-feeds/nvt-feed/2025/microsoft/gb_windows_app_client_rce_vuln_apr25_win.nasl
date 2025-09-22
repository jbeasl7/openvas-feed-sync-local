# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:windows_app";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836104");
  script_version("2025-08-26T05:39:52+0000");
  script_cve_id("CVE-2024-49105");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-12 02:04:36 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"creation_date", value:"2025-04-08 17:39:07 +0530 (Tue, 08 Apr 2025)");
  script_name("Windows App Client RCE Vulnerability (Apr 2025) - Windows");

  script_tag(name:"summary", value:"Windows App Client is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a remote code
  execution vulnerability in Windows App Client.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform remote code execution.");

  script_tag(name:"affected", value:"Microsoft Windows App Client prior to version 2.0.327.0.");

  script_tag(name:"solution", value:"Update to version 2.0.327.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49105");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_windows_app_client_detect_win.nasl");
  script_mandatory_keys("WAClient/Win/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"2.0.327.0")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"2.0.327.0", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

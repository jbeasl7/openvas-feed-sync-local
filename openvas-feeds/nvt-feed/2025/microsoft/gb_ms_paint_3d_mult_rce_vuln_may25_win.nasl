# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:paint_3d";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836361");
  script_version("2025-06-02T05:40:56+0000");
  script_cve_id("CVE-2023-32047", "CVE-2023-35374");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-06-02 05:40:56 +0000 (Mon, 02 Jun 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-11 18:15:20 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2025-05-26 14:57:52 +0530 (Mon, 26 May 2025)");
  script_name("Microsoft Paint 3D Multiple RCE Vulnerabilities (May 2025) - Windows");

  script_tag(name:"summary", value:"Microsoft Paint 3D is prone to multiple remote code execution
  (RCE) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform remote code execution.");

  script_tag(name:"affected", value:"Microsoft Paint 3D prior to version 6.2305.16087.0 on Microsoft Windows.");

  script_tag(name:"solution", value:"Update to version 6.2305.16087.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-32047");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-35374");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");

  script_dependencies("gb_ms_paint_3d_detect_win.nasl");
  script_mandatory_keys("MSPaint3D/Win/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"6.2305.16087.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2305.16087.0", install_path: location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

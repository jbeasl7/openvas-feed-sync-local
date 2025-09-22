# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:3d_viewer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836382");
  script_version("2025-06-02T05:40:56+0000");
  script_cve_id("CVE-2023-36739", "CVE-2023-36740", "CVE-2023-36760");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-06-02 05:40:56 +0000 (Mon, 02 Jun 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-12 17:15:11 +0000 (Tue, 12 Sep 2023)");
  script_tag(name:"creation_date", value:"2025-05-28 15:51:18 +0530 (Wed, 28 May 2025)");
  script_name("Microsoft 3D Viewer < 7.2306.12012.0 Multiple Vulnerabilities (May 2025) - Windows");

  script_tag(name:"summary", value:"Microsoft 3D Viewer is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform remote code execution.");

  script_tag(name:"affected", value:"Microsoft 3D Viewer prior to version 7.2306.12012.0 on Microsoft Windows.");

  script_tag(name:"solution", value:"Update to version 7.2306.12012.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36739");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36740");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36760");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");

  script_dependencies("gb_ms_3d_viewer_detect_win.nasl");
  script_mandatory_keys("MS3DViewer/Win/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"7.2306.12012.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2306.12012.0", install_path: location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

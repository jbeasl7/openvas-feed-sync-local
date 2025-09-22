# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:edge_chromium_based";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834420");
  script_version("2024-08-30T05:05:38+0000");
  script_cve_id("CVE-2024-43472");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-08-30 05:05:38 +0000 (Fri, 30 Aug 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-28 19:13:21 +0000 (Wed, 28 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-20 10:42:42 +0530 (Tue, 20 Aug 2024)");
  script_name("Microsoft Edge (Chromium-Based) Elevation of Privilege Vulnerability - Aug24");

  script_tag(name:"summary", value:"Microsoft Edge (Chromium-Based) is prone to
  an elevation of privilege vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an elevation of
  privilege vulnerability in Microsoft Edge (Chromium-based).");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to gain administrator privileges and view some sensitive information.");

  script_tag(name:"affected", value:"Microsoft Edge (Chromium-Based) prior to  version 127.0.2651.105.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please
  see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43472");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_edge_chromium_based_detect_win.nasl");
  script_mandatory_keys("microsoft_edge_chromium/installed", "microsoft_edge_chromium/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"127.0.2651.105")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"127.0.2651.105", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:edge_chromium_based";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834291");
  script_version("2024-08-19T05:05:38+0000");
  script_cve_id("CVE-2024-6990", "CVE-2024-7255", "CVE-2024-7256");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-08-19 05:05:38 +0000 (Mon, 19 Aug 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-16 15:23:19 +0000 (Fri, 16 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-07 11:11:04 +0530 (Wed, 07 Aug 2024)");
  script_name("Microsoft Edge (Chromium-Based) Multiple Vulnerabilities - Aug24");

  script_tag(name:"summary", value:"Microsoft Edge (Chromium-Based) is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-7255: Out of bounds read in WebTransport

  - CVE-2024-6990: Uninitialized Use in Dawn

  - CVE-2024-7256: Insufficient data validation in Dawn");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute arbitrary code and perform out of bounds memory access via a
  crafted HTML page.");

  script_tag(name:"affected", value:"Microsoft Edge (Chromium-Based) prior to  version 127.0.2651.86.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please
  see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-6990");
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

if(version_is_less(version:vers, test_version:"127.0.2651.86")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"127.0.2651.86", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

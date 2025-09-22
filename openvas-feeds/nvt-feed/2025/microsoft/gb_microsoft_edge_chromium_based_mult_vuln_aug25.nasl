# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:edge_chromium_based";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836574");
  script_version("2025-08-14T05:40:53+0000");
  script_cve_id("CVE-2025-8576", "CVE-2025-8577", "CVE-2025-8578", "CVE-2025-8579",
                "CVE-2025-8580", "CVE-2025-8581", "CVE-2025-8582", "CVE-2025-8583");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-14 05:40:53 +0000 (Thu, 14 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-11 11:38:02 +0530 (Mon, 11 Aug 2025)");
  script_name("Microsoft Edge (Chromium-Based) Multiple Vulnerabilities (Aug 2025)");

  script_tag(name:"summary", value:"Microsoft Edge (Chromium-Based) is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact" , value:"Successful exploitation allows an attacker
  to run arbitrary code, disclose information and conduct denial of service attacks.");

  script_tag(name:"affected", value:"Microsoft Edge (Chromium-Based) prior to version 139.0.3405.86.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please
  see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"139.0.3405.86")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"139.0.3405.86", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
